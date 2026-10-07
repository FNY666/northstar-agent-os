"""Log aggregator interface (Loki-style, single-host).

A ``LogAggregator`` answers the logs question "what was printed, by whom,
when?" without a wall clock. All timestamps are caller-supplied integers;
the module never reads the real clock:

* ``ingest(stream, labels, timestamp_ms, line, seq)`` appends one line to
  the stream identified by ``(stream, labels)``. Returns the stored
  frozen ``LogEntry`` with a ``sha256:`` digest pin.
* ``query(stream=None, labels=None, start=None, end=None, contains=None,
  regex=None, limit=None)`` returns matching entries in ascending
  ``(timestamp_ms, seq)`` order. ``labels`` is an exact subset match
  (Loki ``{app="api",env="prod"}`` selectors); ``contains`` is a Loki
  ``|= "..."`` substring line filter; ``regex`` is a Loki ``|~ "..."``
  regex line filter. Range is ``[start, end)``.
* ``tail(n, stream=None, labels=None)`` returns the last ``n`` entries
  in ascending order (Loki ``tail -n``).
* ``retention(cutoff_ms, seq)`` drops every entry with a timestamp
  strictly older than the caller-supplied cutoff and reports what was
  dropped. The caller supplies the cutoff because this module has no
  clock -- "now" is the host's decision, not the aggregator's.

House style: no wall-clock -- all times are caller-supplied ints.
Frozen records, fail-closed validation, stdlib-only, deterministic,
version/schema pins, ``main()`` self-check.

Honest scope: this is an in-memory bookkeeping interface over
host-reported log records, not a real storage engine. It cannot observe
the log source, cannot prove a missing line was never printed (only that
it is not here), and a matching ``query()`` proves "this reported line
was ingested", never "this fact is true". Audit events carry digest pins
and counts only -- raw log lines are never logged twice.

Version pin: log-aggregator.v1
Schema pin: northstar.log-aggregator.v1
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Tuple

#: Module version.
LOG_AGGREGATOR_VERSION = "log-aggregator.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.log-aggregator.v1"

#: Line size guardrail: one log line may not exceed 1 MiB of UTF-8 bytes.
MAX_LINE_BYTES = 1 << 20

#: Audit event kinds.
AUDIT_CREATED = "created"
AUDIT_INGESTED = "line-ingested"
AUDIT_QUERIED = "queried"
AUDIT_TAILED = "tailed"
AUDIT_RETENTION = "retention-applied"
AUDIT_REJECTED = "rejected"
_AUDIT_KINDS = frozenset(
    {
        AUDIT_CREATED,
        AUDIT_INGESTED,
        AUDIT_QUERIED,
        AUDIT_TAILED,
        AUDIT_RETENTION,
        AUDIT_REJECTED,
    }
)


class LogAggregatorError(ValueError):
    """Base error for log-aggregator validation/rejection (fail-closed)."""


def _require_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise LogAggregatorError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _require_ts_ms(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LogAggregatorError(f"{name} must be a non-negative int, got {value!r}")
    return value


def _require_stream(stream: object) -> str:
    if not isinstance(stream, str) or not stream:
        raise LogAggregatorError(f"stream must be a non-empty str, got {stream!r}")
    return stream


def _require_labels(labels: object) -> Tuple[Tuple[str, str], ...]:
    if labels is None:
        return ()
    if not isinstance(labels, Mapping):
        raise LogAggregatorError(
            f"labels must be a mapping or None, got {type(labels).__name__}"
        )
    out = []
    for key, value in labels.items():
        if not isinstance(key, str) or not key:
            raise LogAggregatorError(f"label keys must be non-empty str, got {key!r}")
        if not isinstance(value, str):
            raise LogAggregatorError(f"label values must be str, got {value!r}")
        out.append((key, value))
    return tuple(sorted(out))


def _require_line(line: object) -> str:
    if not isinstance(line, str) or not line:
        raise LogAggregatorError(f"line must be a non-empty str, got {line!r}")
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise LogAggregatorError(
            f"line exceeds {MAX_LINE_BYTES} bytes of UTF-8"
        )
    return line


def _digest(body: object) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LogEntry:
    """One stored log line."""

    stream: str
    labels: Tuple[Tuple[str, str], ...]
    timestamp_ms: int
    line: str
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "stream": self.stream,
            "labels": dict(self.labels),
            "timestamp_ms": self.timestamp_ms,
            "line": self.line,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TailReport:
    """Outcome of one ``tail()`` call (entries in ascending order)."""

    stream: Optional[str]
    labels: Tuple[Tuple[str, str], ...]
    requested: int
    entries: Tuple[LogEntry, ...]
    seq: int

    def as_dict(self) -> dict:
        return {
            "stream": self.stream,
            "labels": dict(self.labels),
            "requested": self.requested,
            "returned": len(self.entries),
            "entry_digests": [e.digest for e in self.entries],
            "seq": self.seq,
        }


@dataclass(frozen=True)
class RetentionReport:
    """Outcome of one ``retention()`` call."""

    cutoff_ms: int
    streams_visited: int
    entries_dropped: int
    entries_kept: int
    seq: int

    def as_dict(self) -> dict:
        return {
            "cutoff_ms": self.cutoff_ms,
            "streams_visited": self.streams_visited,
            "entries_dropped": self.entries_dropped,
            "entries_kept": self.entries_kept,
            "seq": self.seq,
        }


class LogAggregator:
    """In-memory log store: streams keyed by (stream, sorted label pairs)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # key -> list[LogEntry], insertion order preserved.
        self._streams: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], list[LogEntry]] = {}
        self._ingests = 0

    def _key(
        self, stream: str, labels: Tuple[Tuple[str, str], ...]
    ) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
        return (stream, labels)

    def ingest(
        self,
        stream: object,
        labels: object,
        timestamp_ms: object,
        line: object,
        seq: object,
    ) -> LogEntry:
        """Append one log line; returns the stored (frozen) record."""
        stream = _require_stream(stream)
        labels = _require_labels(labels)
        timestamp_ms = _require_ts_ms("timestamp_ms", timestamp_ms)
        line = _require_line(line)
        seq = _require_seq(seq)
        digest = _digest(
            {
                "stream": stream,
                "labels": dict(labels),
                "timestamp_ms": timestamp_ms,
                "line": line,
                "seq": seq,
            }
        )
        entry = LogEntry(
            stream=stream,
            labels=labels,
            timestamp_ms=timestamp_ms,
            line=line,
            seq=seq,
            digest=digest,
        )
        with self._lock:
            key = self._key(stream, labels)
            self._streams.setdefault(key, []).append(entry)
            self._ingests += 1
        return entry

    def _matching_keys(
        self,
        stream: Optional[str],
        labels: Tuple[Tuple[str, str], ...],
    ) -> list[Tuple[str, Tuple[Tuple[str, str], ...]]]:
        # stream/labels arrive already validated by the caller.
        want = dict(labels)
        return [
            key
            for key in self._streams
            if (stream is None or key[0] == stream)
            and all(dict(key[1]).get(k) == v for k, v in want.items())
        ]

    def query(
        self,
        stream: object = None,
        labels: object = None,
        start: object = None,
        end: object = None,
        contains: object = None,
        regex: object = None,
        limit: object = None,
    ) -> Tuple[LogEntry, ...]:
        """Entries matching stream + label subset within [start, end).

        ``contains`` is a substring line filter (Loki ``|=``);
        ``regex`` is a regex line filter (Loki ``|~``); ``limit`` caps
        the number of returned entries. Results are sorted ascending by
        ``(timestamp_ms, seq)`` for deterministic audit replay.
        """
        if stream is not None:
            stream = _require_stream(stream)
        labels = _require_labels(labels)
        start_ts: Optional[int] = None if start is None else _require_ts_ms("start", start)
        end_ts: Optional[int] = None if end is None else _require_ts_ms("end", end)
        if start_ts is not None and end_ts is not None and start_ts > end_ts:
            raise LogAggregatorError(f"start ({start_ts}) must not exceed end ({end_ts})")
        needle: Optional[str] = None
        if contains is not None:
            if not isinstance(contains, str) or not contains:
                raise LogAggregatorError(
                    f"contains must be a non-empty str, got {contains!r}"
                )
            needle = contains
        pattern: Optional[re.Pattern] = None
        if regex is not None:
            if not isinstance(regex, str) or not regex:
                raise LogAggregatorError(f"regex must be a non-empty str, got {regex!r}")
            try:
                pattern = re.compile(regex)
            except re.error as exc:
                raise LogAggregatorError(f"invalid regex {regex!r}: {exc}") from exc
        limit_n: Optional[int] = None
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                raise LogAggregatorError(f"limit must be a positive int, got {limit!r}")
            limit_n = limit
        entries: list[LogEntry] = []
        with self._lock:
            keys = self._matching_keys(stream, labels)
            for key in keys:
                for entry in self._streams[key]:
                    if start_ts is not None and entry.timestamp_ms < start_ts:
                        continue
                    if end_ts is not None and entry.timestamp_ms >= end_ts:
                        continue
                    if needle is not None and needle not in entry.line:
                        continue
                    if pattern is not None and not pattern.search(entry.line):
                        continue
                    entries.append(entry)
        entries.sort(key=lambda e: (e.timestamp_ms, e.seq))
        if limit_n is not None:
            entries = entries[:limit_n]
        return tuple(entries)

    def tail(
        self,
        n: object,
        stream: object = None,
        labels: object = None,
        seq: object = 0,
    ) -> TailReport:
        """The last ``n`` entries in ascending ``(timestamp_ms, seq)`` order."""
        if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
            raise LogAggregatorError(f"n must be a positive int, got {n!r}")
        if stream is not None:
            stream = _require_stream(stream)
        labels = _require_labels(labels)
        seq = _require_seq(seq)
        entries: list[LogEntry] = []
        with self._lock:
            for key in self._matching_keys(stream, labels):
                entries.extend(self._streams[key])
        entries.sort(key=lambda e: (e.timestamp_ms, e.seq))
        picked = tuple(entries[-n:]) if len(entries) > n else tuple(entries)
        return TailReport(
            stream=stream, labels=labels, requested=n, entries=picked, seq=seq
        )

    def retention(self, cutoff_ms: object, seq: object) -> RetentionReport:
        """Drop every entry strictly older than ``cutoff_ms``.

        Emptied streams are purged from the registry. The caller supplies
        the cutoff (no wall clock); ``retention()`` trusts the host's
        "now" -- it only drops older entries.
        """
        cutoff_ms = _require_ts_ms("cutoff_ms", cutoff_ms)
        seq = _require_seq(seq)
        dropped = 0
        kept = 0
        visited = 0
        with self._lock:
            for key in list(self._streams.keys()):
                visited += 1
                entries = self._streams[key]
                survivors = [e for e in entries if e.timestamp_ms >= cutoff_ms]
                dropped += len(entries) - len(survivors)
                kept += len(survivors)
                if survivors:
                    self._streams[key] = survivors
                else:
                    del self._streams[key]
        return RetentionReport(
            cutoff_ms=cutoff_ms,
            streams_visited=visited,
            entries_dropped=dropped,
            entries_kept=kept,
            seq=seq,
        )

    def stream_count(self) -> int:
        """Number of live (non-empty) streams."""
        with self._lock:
            return len(self._streams)

    def entry_count(self) -> int:
        """Number of stored log entries across all streams."""
        with self._lock:
            return sum(len(entries) for entries in self._streams.values())

    def streams(self) -> Tuple[Tuple[str, Tuple[Tuple[str, str], ...]], ...]:
        """Sorted (stream, labels) keys currently registered."""
        with self._lock:
            return tuple(sorted(self._streams.keys()))

    def verify(self) -> bool:
        """Recompute every entry digest; ``False`` on any tamper."""
        with self._lock:
            for entries in self._streams.values():
                for entry in entries:
                    expected = _digest(
                        {
                            "stream": entry.stream,
                            "labels": dict(entry.labels),
                            "timestamp_ms": entry.timestamp_ms,
                            "line": entry.line,
                            "seq": entry.seq,
                        }
                    )
                    if expected != entry.digest:
                        return False
        return True


def log_aggregator_audit_event(kind: str, seq: int, **fields) -> dict:
    """Shape one ``audit.ndjson/1`` record for this module.

    Carries digest pins, stream names, and counts only -- raw log lines
    are never emitted into the audit stream.
    """
    if kind not in _AUDIT_KINDS:
        raise LogAggregatorError(f"unknown audit kind: {kind!r}")
    _require_seq(seq)
    event: dict = {
        "schema": SCHEMA_PIN,
        "audit_seq": seq,
        "kind": kind,
        "module_version": LOG_AGGREGATOR_VERSION,
    }
    event.update(fields)
    return event


def main() -> None:
    agg = LogAggregator()
    agg.ingest("app", {"host": "a"}, 1000, "starting up", 0)
    agg.ingest("app", {"host": "a"}, 2000, "error: disk full", 1)
    agg.ingest("app", {"host": "b"}, 1000, "starting up", 2)
    assert agg.entry_count() == 3
    assert agg.stream_count() == 2
    # Label subset match.
    got = agg.query(labels={"host": "a"})
    assert len(got) == 2 and got[0].timestamp_ms == 1000, got
    # Substring line filter.
    got = agg.query(contains="error")
    assert len(got) == 1 and "disk full" in got[0].line, got
    # Regex line filter.
    got = agg.query(regex=r"^start")
    assert len(got) == 2, got
    # Range filtering: [start, end).
    got = agg.query(start=1000, end=2000)
    assert len(got) == 2, got
    # Digest pins.
    assert all(e.digest.startswith("sha256:") for e in got)
    assert agg.verify()
    # Tail: last 2 across all streams, ascending.
    report = agg.tail(2, seq=3)
    assert len(report.entries) == 2, report.as_dict()
    assert report.entries[0].timestamp_ms <= report.entries[1].timestamp_ms
    # Limit caps results.
    got = agg.query(limit=1)
    assert len(got) == 1, got
    # Retention drops strictly-older entries.
    dropped = agg.retention(2000, 4)
    assert dropped.entries_dropped == 2 and dropped.entries_kept == 1, dropped.as_dict()
    assert agg.entry_count() == 1
    assert agg.stream_count() == 1  # emptied stream purged
    assert agg.verify()
    print("log-aggregator OK: ingest, query, tail, retention")


if __name__ == "__main__":
    main()
