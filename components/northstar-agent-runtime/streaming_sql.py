"""Streaming SQL interface (Flink-style windows and aggregations).

A deterministic, network-free window/aggregation engine for event streams:
events are host-reported rows ``{"event_time": int, "value": ...}`` (no
wall-clock — all time is caller-supplied integer event time).

1. **`TumblingWindow`** — fixed-size, non-overlapping windows:
   ``window_start = (event_time // size) * size``.
2. **`SlidingWindow`** — fixed-size windows that advance by a slide:
   an event at time ``t`` belongs to every window ``[w, w+size)`` with
   ``w = k*slide <= t < w+size``.
3. **`StreamingSQL.aggregate(rows, window, agg)`** — groups rows by their
   window assignment and folds each group with one of ``count``, ``sum``,
   ``min``, ``max``, ``avg``. Aggregation is deterministic: windows are
   emitted in ascending start order, values fold in ingestion order.

Watermarks: :meth:`StreamingSQL.watermark` computes the per-window
completeness bound (max event time seen minus allowed lateness); windows
below the watermark are *complete*, later rows for them are *late* and
refused rather than silently re-aggregated (fail-closed).

House style: stdlib-only (``hashlib``, ``math``, ``dataclasses``),
deterministic, no wall-clock, fail-closed validation (bool/negative
seqs, bad windows rejected), frozen records with version/schema pins,
``main()`` self-check.

Honest scope: interface + bookkeeping, not a real stream processor —
no network, no checkpoints, no exactly-once semantics, no keyed state
across partitions. Events are host-reported; late-event policy is the
host's choice via ``allowed_lateness``. This is a single-node window
aggregator; production deployments need watermark coordination across
sources, which lives outside this module.

Version pin: streaming-sql.v1
Schema pin: northstar.streaming-sql.v1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Sequence, Tuple

#: Module version pin.
STREAMING_SQL_VERSION = "streaming-sql.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.streaming-sql.v1"

#: Supported aggregation functions.
AGG_FUNCS = frozenset({"count", "sum", "min", "max", "avg"})

#: Fixed vocabulary for audit events.
_AUDIT_KINDS = frozenset({
    "windowed", "aggregated", "watermark-advanced", "late-refused", "rejected",
})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class StreamingSQLError(Exception):
    """Base error for streaming SQL."""


class WindowError(StreamingSQLError):
    """A window specification or assignment is invalid."""


class LateEventError(StreamingSQLError):
    """An event arrived after its window was marked complete."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_int(name: str, value: Any, *, allow_negative: bool = False,
               allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if not allow_zero and value <= 0:
        raise ValueError(f"{name} must be positive")
    if not allow_negative and value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _check_str(name: str, value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    return value


def _check_number(name: str, value: Any) -> float:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be a number, got bool")
    if isinstance(value, (int, float)):
        return float(value)
    raise TypeError(f"{name} must be a number, got {type(value).__name__}")


def _check_row(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"row must be a mapping, got {type(value).__name__}")
    row = dict(value)
    if "event_time" not in row:
        raise ValueError("row must carry 'event_time'")
    _check_int("event_time", row["event_time"], allow_zero=True)
    return row


def _canonical_bytes(obj: Any) -> bytes:
    import json
    text = json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))
    return text.encode("utf-8")


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


# ---------------------------------------------------------------------------
# Window specs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TumblingWindow:
    """Fixed-size, non-overlapping windows of ``size`` event-time units."""

    size: int
    version: str = field(default=STREAMING_SQL_VERSION, init=False)
    schema: str = field(default=SCHEMA_PIN, init=False)

    def __post_init__(self) -> None:
        _check_int("size", self.size)

    def assign(self, event_time: int) -> Tuple[int, int]:
        """Return the single ``(start, end)`` window containing the event."""
        t = _check_int("event_time", event_time, allow_zero=True)
        start = (t // self.size) * self.size
        return (start, start + self.size)

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": "tumbling", "size": self.size,
                "version": self.version, "schema": self.schema}


@dataclass(frozen=True)
class SlidingWindow:
    """Size-``size`` windows advancing every ``slide`` time units."""

    size: int
    slide: int
    version: str = field(default=STREAMING_SQL_VERSION, init=False)
    schema: str = field(default=SCHEMA_PIN, init=False)

    def __post_init__(self) -> None:
        _check_int("size", self.size)
        _check_int("slide", self.slide)
        if self.slide > self.size:
            raise WindowError("slide must not exceed size (gaps not supported)")

    def assign(self, event_time: int) -> Tuple[Tuple[int, int], ...]:
        """Return every ``(start, end)`` window containing the event."""
        t = _check_int("event_time", event_time, allow_zero=True)
        # Earliest window start containing t: smallest k with k*slide + size > t.
        k_min = (t - self.size + self.slide) // self.slide
        if k_min < 0:
            k_min = 0
        k_max = t // self.slide
        out = []
        for k in range(k_min, k_max + 1):
            start = k * self.slide
            out.append((start, start + self.size))
        return tuple(out)

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": "sliding", "size": self.size, "slide": self.slide,
                "version": self.version, "schema": self.schema}


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WindowResult:
    """Aggregated result for one window."""

    window_start: int
    window_end: int
    agg: str
    value: Any
    row_count: int
    digest: str

    def __post_init__(self) -> None:
        if self.agg not in AGG_FUNCS:
            raise ValueError(f"unknown agg: {self.agg!r}")
        if not (isinstance(self.digest, str) and
                self.digest.startswith("sha256:")):
            raise ValueError("digest must be a sha256: pin")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "window_start": self.window_start,
            "window_end": self.window_end,
            "agg": self.agg,
            "value": self.value,
            "row_count": self.row_count,
            "digest": self.digest,
            "version": STREAMING_SQL_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class WatermarkReport:
    """Completeness bound of a stream given an allowed lateness."""

    max_event_time: int
    allowed_lateness: int
    watermark: int
    version: str = field(default=STREAMING_SQL_VERSION, init=False)
    schema: str = field(default=SCHEMA_PIN, init=False)

    def __post_init__(self) -> None:
        _check_int("max_event_time", self.max_event_time, allow_zero=True)
        _check_int("allowed_lateness", self.allowed_lateness, allow_zero=True)
        _check_int("watermark", self.watermark, allow_zero=True)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "max_event_time": self.max_event_time,
            "allowed_lateness": self.allowed_lateness,
            "watermark": self.watermark,
            "version": self.version,
            "schema": self.schema,
        }


class StreamingSQL:
    """Flink-style window aggregation with watermark-based completeness."""

    def __init__(self, *, allowed_lateness: int = 0) -> None:
        self._allowed_lateness = _check_int(
            "allowed_lateness", allowed_lateness, allow_zero=True)
        self._max_seen: int | None = None

    @property
    def allowed_lateness(self) -> int:
        return self._allowed_lateness

    def _windows_for(self, window: Any, event_time: int) -> Sequence[Tuple[int, int]]:
        if isinstance(window, TumblingWindow):
            return (window.assign(event_time),)
        if isinstance(window, SlidingWindow):
            return window.assign(event_time)
        raise TypeError(
            f"window must be TumblingWindow or SlidingWindow, "
            f"got {type(window).__name__}")

    def tumbling_window(self, size: int) -> TumblingWindow:
        """Build a tumbling window of ``size``."""
        return TumblingWindow(size)

    def sliding_window(self, size: int, slide: int) -> SlidingWindow:
        """Build a sliding window of ``size`` advancing by ``slide``."""
        return SlidingWindow(size, slide)

    def watermark(self) -> WatermarkReport | None:
        """Current watermark, or ``None`` when no events have been seen."""
        if self._max_seen is None:
            return None
        wm = self._max_seen - self._allowed_lateness
        return WatermarkReport(
            max_event_time=self._max_seen,
            allowed_lateness=self._allowed_lateness,
            watermark=max(wm, 0),
        )

    def _is_late(self, window_end: int) -> bool:
        if self._max_seen is None:
            return False
        return window_end <= self._max_seen - self._allowed_lateness

    def ingest(self, rows: Sequence[Any], window: Any,
               seq: int) -> Tuple[Dict[Tuple[int, int], List[Dict[str, Any]]], int]:
        """Assign rows to windows; updates the event-time max.

        Returns ``(buckets, ingested)`` where ``buckets`` maps each window
        ``(start, end)`` to the rows it contains, in ingestion order.
        Rows whose every window is complete are refused fail-closed with
        :class:`LateEventError`.
        """
        _check_int("seq", seq, allow_zero=True)
        buckets: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}
        ingested = 0
        for raw in rows:
            row = _check_row(raw)
            t = row["event_time"]
            if self._max_seen is None or t > self._max_seen:
                self._max_seen = t
            wins = self._windows_for(window, t)
            kept = [w for w in wins if not self._is_late(w[1])]
            if not kept:
                raise LateEventError(
                    f"event_time {t}: all windows already complete")
            for w in kept:
                buckets.setdefault(w, []).append(row)
            ingested += 1
        return buckets, ingested

    @staticmethod
    def _fold(rows: Sequence[Mapping[str, Any]], agg: str) -> Any:
        if agg == "count":
            return len(rows)
        values = [_check_number("value", r.get("value")) for r in rows]
        if agg == "sum":
            return sum(values)
        if agg == "min":
            return min(values)
        if agg == "max":
            return max(values)
        if agg == "avg":
            return sum(values) / len(values)
        raise ValueError(f"unknown agg: {agg!r}")  # pragma: no cover

    def aggregate(self, rows: Sequence[Any], window: Any, agg: str,
                  seq: int) -> List[WindowResult]:
        """Assign rows to windows and fold each window with ``agg``."""
        _check_int("seq", seq, allow_zero=True)
        if not isinstance(agg, str):
            raise TypeError(f"agg must be a str, got {type(agg).__name__}")
        if agg not in AGG_FUNCS:
            raise ValueError(f"unknown agg: {agg!r}")
        buckets, _ = self.ingest(rows, window, seq)
        results: List[WindowResult] = []
        for (start, end) in sorted(buckets):
            wrows = buckets[(start, end)]
            value = self._fold(wrows, agg)
            digest = _pin({
                "window_start": start, "window_end": end, "agg": agg,
                "value": value, "row_count": len(wrows),
            })
            results.append(WindowResult(start, end, agg, value, len(wrows),
                                       digest))
        return results


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def streaming_sql_audit_event(kind: str, seq: int,
                              detail: str = "") -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for streaming-SQL decisions."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown kind: {kind!r}")
    _check_int("seq", seq, allow_zero=True)
    if not isinstance(detail, str):
        raise TypeError("detail must be a str")
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "kind": kind,
        "audit_seq": seq,
    }
    if detail:
        event["detail"] = detail
    return event


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    sql = StreamingSQL()
    rows = [{"event_time": t, "value": v}
            for t, v in [(1, 10), (2, 20), (6, 30), (7, 40), (11, 50)]]
    tum = sql.tumbling_window(5)
    out = sql.aggregate(rows, tum, "sum", 0)
    got = [(r.window_start, r.window_end, r.value, r.row_count) for r in out]
    assert got == [(0, 5, 30, 2), (5, 10, 70, 2), (10, 15, 50, 1)], got
    slid = sql.sliding_window(6, 3)
    w0 = slid.assign(4)
    assert w0 == ((0, 6), (3, 9)), w0
    # Watermark: max_seen=11, lateness 0 -> window end <= 11 is complete.
    late = StreamingSQL()
    late.aggregate(rows, tum, "count", 0)
    wm = late.watermark()
    assert wm is not None and wm.watermark == 11, wm
    try:
        late.aggregate([{"event_time": 3, "value": 1}], tum, "count", 1)
    except LateEventError:
        pass
    else:
        raise AssertionError("late event must be refused")
    avg = StreamingSQL().aggregate(rows, tum, "avg", 2)
    assert avg[0].value == 15.0, avg
    print("streaming-sql OK: tumbling, sliding, aggregate, watermark, late-refusal")


if __name__ == "__main__":
    main()
