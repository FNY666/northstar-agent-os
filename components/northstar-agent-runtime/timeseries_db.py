"""Time-series database (TSDB) interface (Prometheus/InfluxDB-style, single-host).

A ``TimeseriesDB`` answers the metrics question "what was this value
over time?" without a wall clock. All timestamps are caller-supplied
integers; the module never reads the real clock:

* ``write(metric, labels, timestamp_ms, value, seq)`` appends one point
  to the series identified by ``(metric, labels)``.
* ``query(metric, labels=None, start=None, end=None)`` returns the
  matching points in ascending timestamp order. ``labels`` is an exact
  subset match (empty/``None`` matches every series under the metric).
* ``downsample(metric, labels, bucket_ms, agg, start, end)`` folds
  points into tumbling buckets ``[k*bucket_ms, (k+1)*bucket_ms)`` with
  ``count``/``sum``/``min``/``max``/``avg``. Each bucket carries a
  ``sha256:`` digest pin so a result is verifiable later.
* ``retention(cutoff_ms, seq)`` drops every point with a timestamp
  strictly older than the caller-supplied cutoff and reports what was
  dropped. The caller supplies the cutoff because this module has no
  clock -- "now" is the host's decision, not the database's.

House style: no wall-clock -- all times are caller-supplied ints.
Frozen records, fail-closed validation, stdlib-only, deterministic,
version/schema pins, ``main()`` self-check.

Honest scope: this is an in-memory bookkeeping interface over
host-reported values, not a real storage engine. It cannot verify a
reported value was actually measured, cannot prove a missing point was
never written (only that it is not here), and ``retention()`` cannot
prove the host's "now" was truthful -- it only drops older points.

Version pin: timeseries-db.v1
Schema pin: northstar.timeseries-db.v1
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Tuple

#: Module version.
TIMESERIES_DB_VERSION = "timeseries-db.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.timeseries-db.v1"

#: Supported downsampling aggregations.
AGG_COUNT = "count"
AGG_SUM = "sum"
AGG_MIN = "min"
AGG_MAX = "max"
AGG_AVG = "avg"
_AGGS = frozenset({AGG_COUNT, AGG_SUM, AGG_MIN, AGG_MAX, AGG_AVG})

#: Audit event kinds.
AUDIT_CREATED = "created"
AUDIT_WRITTEN = "point-written"
AUDIT_QUERIED = "queried"
AUDIT_DOWNSAMPLED = "downsampled"
AUDIT_RETENTION = "retention-applied"
AUDIT_REJECTED = "rejected"
_AUDIT_KINDS = frozenset(
    {
        AUDIT_CREATED,
        AUDIT_WRITTEN,
        AUDIT_QUERIED,
        AUDIT_DOWNSAMPLED,
        AUDIT_RETENTION,
        AUDIT_REJECTED,
    }
)


class TimeseriesError(ValueError):
    """Base error for TSDB validation/rejection (fail-closed)."""


class UnknownMetricError(TimeseriesError):
    """A metric/series was addressed but nothing matches."""


def _require_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise TimeseriesError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _require_ts_ms(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TimeseriesError(f"{name} must be a non-negative int, got {value!r}")
    return value


def _require_metric(metric: object) -> str:
    if not isinstance(metric, str) or not metric:
        raise TimeseriesError(f"metric must be a non-empty str, got {metric!r}")
    return metric


def _require_labels(labels: object) -> Tuple[Tuple[str, str], ...]:
    if labels is None:
        return ()
    if not isinstance(labels, Mapping):
        raise TimeseriesError(f"labels must be a mapping or None, got {type(labels).__name__}")
    out = []
    for key, value in labels.items():
        if not isinstance(key, str) or not key:
            raise TimeseriesError(f"label keys must be non-empty str, got {key!r}")
        if not isinstance(value, str):
            raise TimeseriesError(f"label values must be str, got {value!r}")
        out.append((key, value))
    return tuple(sorted(out))


def _require_value(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TimeseriesError(f"value must be a real number, got {value!r}")
    value = float(value)
    if not math.isfinite(value):
        raise TimeseriesError(f"value must be finite, got {value!r}")
    return value


def _digest(body: object) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Point:
    """One stored time-series sample."""

    metric: str
    labels: Tuple[Tuple[str, str], ...]
    timestamp_ms: int
    value: float
    seq: int

    def as_dict(self) -> dict:
        return {
            "metric": self.metric,
            "labels": dict(self.labels),
            "timestamp_ms": self.timestamp_ms,
            "value": self.value,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class BucketResult:
    """One downsampled tumbling bucket."""

    metric: str
    labels: Tuple[Tuple[str, str], ...]
    bucket_start_ms: int
    bucket_end_ms: int
    agg: str
    count: int
    value: Optional[float]
    digest: str

    def as_dict(self) -> dict:
        return {
            "metric": self.metric,
            "labels": dict(self.labels),
            "bucket_start_ms": self.bucket_start_ms,
            "bucket_end_ms": self.bucket_end_ms,
            "agg": self.agg,
            "count": self.count,
            "value": self.value,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RetentionReport:
    """Outcome of one ``retention()`` call."""

    cutoff_ms: int
    series_visited: int
    points_dropped: int
    points_kept: int
    seq: int

    def as_dict(self) -> dict:
        return {
            "cutoff_ms": self.cutoff_ms,
            "series_visited": self.series_visited,
            "points_dropped": self.points_dropped,
            "points_kept": self.points_kept,
            "seq": self.seq,
        }


class TimeseriesDB:
    """In-memory TSDB: series keyed by (metric, sorted label pairs)."""

    def __init__(self) -> None:
        # key -> list[Point], insertion order preserved.
        self._series: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], list[Point]] = {}
        self._writes = 0

    def _key(self, metric: str, labels: Tuple[Tuple[str, str], ...]) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
        return (metric, labels)

    def write(
        self,
        metric: object,
        labels: object,
        timestamp_ms: object,
        value: object,
        seq: object,
    ) -> Point:
        """Append one point; returns the stored (frozen) record."""
        metric = _require_metric(metric)
        labels = _require_labels(labels)
        timestamp_ms = _require_ts_ms("timestamp_ms", timestamp_ms)
        value = _require_value(value)
        seq = _require_seq(seq)
        point = Point(
            metric=metric,
            labels=labels,
            timestamp_ms=timestamp_ms,
            value=value,
            seq=seq,
        )
        key = self._key(metric, labels)
        self._series.setdefault(key, []).append(point)
        self._writes += 1
        return point

    def _matching_keys(
        self,
        metric: str,
        labels: Tuple[Tuple[str, str], ...],
    ) -> list[Tuple[str, Tuple[Tuple[str, str], ...]]]:
        # metric/labels arrive already validated by the caller.
        want = dict(labels)
        return [
            key
            for key in self._series
            if key[0] == metric and all(dict(key[1]).get(k) == v for k, v in want.items())
        ]

    def query(
        self,
        metric: object,
        labels: object = None,
        start: object = None,
        end: object = None,
    ) -> Tuple[Point, ...]:
        """Points matching metric + label subset within [start, end)."""
        metric = _require_metric(metric)
        labels = _require_labels(labels)
        start_ts: Optional[int] = None if start is None else _require_ts_ms("start", start)
        end_ts: Optional[int] = None if end is None else _require_ts_ms("end", end)
        if start_ts is not None and end_ts is not None and start_ts > end_ts:
            raise TimeseriesError(f"start ({start_ts}) must not exceed end ({end_ts})")
        points: list[Point] = []
        for key in self._matching_keys(metric, labels):
            for point in self._series[key]:
                if start_ts is not None and point.timestamp_ms < start_ts:
                    continue
                if end_ts is not None and point.timestamp_ms >= end_ts:
                    continue
                points.append(point)
        points.sort(key=lambda p: (p.timestamp_ms, p.seq))
        return tuple(points)

    def downsample(
        self,
        metric: object,
        labels: object,
        bucket_ms: object,
        agg: object,
        start: object,
        end: object,
        seq: object,
    ) -> Tuple[BucketResult, ...]:
        """Tumble points in [start, end) into bucket_ms buckets; aggregate."""
        metric = _require_metric(metric)
        labels = _require_labels(labels)
        if isinstance(bucket_ms, bool) or not isinstance(bucket_ms, int) or bucket_ms <= 0:
            raise TimeseriesError(f"bucket_ms must be a positive int, got {bucket_ms!r}")
        if agg not in _AGGS:
            raise TimeseriesError(f"unknown agg: {agg!r} (want one of {sorted(_AGGS)})")
        start_ts = _require_ts_ms("start", start)
        end_ts = _require_ts_ms("end", end)
        if start_ts > end_ts:
            raise TimeseriesError(f"start ({start_ts}) must not exceed end ({end_ts})")
        seq = _require_seq(seq)

        buckets: Dict[int, list[float]] = {}
        for key in self._matching_keys(metric, labels):
            for point in self._series[key]:
                if point.timestamp_ms < start_ts or point.timestamp_ms >= end_ts:
                    continue
                bucket_start = (point.timestamp_ms // bucket_ms) * bucket_ms
                buckets.setdefault(bucket_start, []).append(point.value)

        results = []
        for bucket_start in sorted(buckets):
            values = buckets[bucket_start]
            count = len(values)
            if agg == AGG_COUNT:
                value: Optional[float] = float(count)
            elif agg == AGG_SUM:
                value = float(math.fsum(values))
            elif agg == AGG_MIN:
                value = float(min(values))
            elif agg == AGG_MAX:
                value = float(max(values))
            else:  # AGG_AVG
                value = float(math.fsum(values) / count)
            digest = _digest(
                [metric, [list(p) for p in labels], bucket_start, bucket_start + bucket_ms, agg, count, value]
            )
            results.append(
                BucketResult(
                    metric=metric,
                    labels=labels,
                    bucket_start_ms=bucket_start,
                    bucket_end_ms=bucket_start + bucket_ms,
                    agg=agg,
                    count=count,
                    value=value,
                    digest=digest,
                )
            )
        return tuple(results)

    def retention(self, cutoff_ms: object, seq: object) -> RetentionReport:
        """Drop every point with timestamp strictly older than ``cutoff_ms``."""
        cutoff = _require_ts_ms("cutoff_ms", cutoff_ms)
        seq = _require_seq(seq)
        dropped = 0
        kept = 0
        visited = 0
        for key in list(self._series):
            visited += 1
            remaining = [p for p in self._series[key] if p.timestamp_ms >= cutoff]
            dropped += len(self._series[key]) - len(remaining)
            kept += len(remaining)
            if remaining:
                self._series[key] = remaining
            else:
                del self._series[key]
        return RetentionReport(
            cutoff_ms=cutoff,
            series_visited=visited,
            points_dropped=dropped,
            points_kept=kept,
            seq=seq,
        )

    def series(self) -> Tuple[Tuple[str, Tuple[Tuple[str, str], ...]], ...]:
        """All (metric, labels) keys currently holding at least one point."""
        return tuple(sorted(self._series))

    def point_count(self) -> int:
        return sum(len(points) for points in self._series.values())


def timeseries_db_audit_event(kind: str, seq: int, **fields) -> dict:
    """Audit-shaped record for a TSDB transition."""
    if kind not in _AUDIT_KINDS:
        raise TimeseriesError(f"unknown audit kind: {kind!r}")
    _require_seq(seq)
    event: dict = {
        "schema": SCHEMA_PIN,
        "audit_seq": seq,
        "kind": kind,
        "module_version": TIMESERIES_DB_VERSION,
    }
    event.update(fields)
    return event


def main() -> None:
    db = TimeseriesDB()
    db.write("cpu", {"host": "a"}, 1000, 0.5, 0)
    db.write("cpu", {"host": "a"}, 2000, 0.7, 1)
    db.write("cpu", {"host": "b"}, 1000, 0.3, 2)
    # Query with label subset match.
    got = db.query("cpu", {"host": "a"})
    assert len(got) == 2 and got[0].timestamp_ms == 1000, got
    assert db.point_count() == 3
    # Downsample both hosts, 1s buckets, avg.
    buckets = db.downsample("cpu", None, 1000, "avg", 0, 3000, 3)
    assert len(buckets) == 2, buckets
    assert buckets[0].bucket_start_ms == 1000 and buckets[0].count == 2
    assert buckets[0].value == 0.4, buckets[0].value  # (0.5 + 0.3) / 2
    assert buckets[0].digest.startswith("sha256:"), buckets[0].digest
    # Range filtering: [start, end).
    got = db.query("cpu", None, 1000, 2000)
    assert len(got) == 2, got
    # Retention drops strictly-older points.
    report = db.retention(2000, 4)
    assert report.points_dropped == 2 and report.points_kept == 1, report.as_dict()
    assert db.point_count() == 1
    print("timeseries-db OK: write, query, downsample, retention")


if __name__ == "__main__":
    main()
