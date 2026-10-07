"""Time-series database: InfluxDB-shaped write/query/downsample bookkeeping.

Research note: a time-series store differs from a relational or document
store in three ways. First, *writes are append-only points* — a point is a
(measurement, tag set, field set, timestamp) tuple; nothing is ever
updated in place. Second, *tags are the query key*: a measurement's series
cardinality is the number of distinct tag sets, and every query filters on
measurement + tags + time range before touching fields. Third, *reads are
windowed*: dashboards never pull raw points, they pull *rollups* — a
downsample pass buckets points by ``floor(ts / window) * window`` and
applies one aggregator per bucket (mean/sum/min/max/count). This module
books all three stages; the host owns storage, retention, and execution.

* **write(measurement, tags, fields, seq, timestamp=None)** — books one
  point. Measurements and tag keys auto-register on first write
  (InfluxDB semantics); ``timestamp`` is a logical seq (never wall-clock)
  and defaults to the mutation ``seq``. Field values are int/float/str/
  bool, type-tagged before digest pinning (bool != int, ``|int| < 2**53``,
  floats must be finite, strings bounded).
* **query(measurement, seq, tags=None, start=None, stop=None)** — pure read
  view: books nothing, consumes no seq, writes no audit row. Returns the
  matching points as data; an unknown measurement or an empty range is an
  empty report, never raised.
* **downsample(measurement, seq, window_seqs, aggregator="mean", ...)** —
  books one rollup pass over the measurement's points (optionally
  tag-filtered and time-ranged). ``mean`` is reported as exact ``"sum/
  count"`` text (no floats); ``sum`` is an int when every input is an int,
  else a float; ``min``/``max`` keep the input type; ``count`` counts
  points per bucket. Bucket order and field order are deterministic, so
  two instances holding the same points pin identical rollup digests.

Fail-closed: malformed measurements/tags/fields/timestamps/windows/
aggregators and out-of-order seqs are programming errors and raise
:class:`TimeSeriesDBError`. A query or rollup that matches nothing is
*data*, not an error. Raw field values and tag values never cross the
audit boundary — audit rows carry digests and counts only.

Honest scope: this is *bookkeeping* for a time-series interface, not a
storage engine. Writes book declared points; a ``PointRecord`` is a
decision, not proof the host persisted anything. Downsample results are
ledger truth, never wire truth. No cross-instance coherence is provided.

Version pin: time-series-db.v1
Schema pin: northstar.time-series-db.v1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

#: Module version.
TIME_SERIES_DB_VERSION = "time-series-db.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.time-series-db.v1"

#: Schema pin for audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned aggregator vocabulary.
AGGREGATORS = ("mean", "sum", "min", "max", "count")

_MAX_MEASUREMENT_LEN = 256
_MAX_TAG_KEY_LEN = 256
_MAX_TAG_VALUE_LEN = 1024
_MAX_FIELD_KEY_LEN = 256
_MAX_STRING_FIELD_LEN = 1024
_MAX_SAFE_INT = 2**53


class TimeSeriesDBError(Exception):
    """Malformed use of the time-series bookkeeping contract (programming error)."""


class BadMeasurementError(TimeSeriesDBError):
    """Measurement name failed validation (non-str, empty, or too long)."""


class BadTagError(TimeSeriesDBError):
    """A tag key/value failed validation."""


class BadFieldError(TimeSeriesDBError):
    """A field name/value failed validation."""


class BadTimestampError(TimeSeriesDBError):
    """A timestamp failed validation (non-int, negative, or bool)."""


class BadWindowError(TimeSeriesDBError):
    """A downsample window failed validation (non-int or non-positive)."""


class BadAggregatorError(TimeSeriesDBError):
    """An aggregator name is not in the pinned vocabulary."""


class SeqOrderError(TimeSeriesDBError):
    """seq failed validation (non-int, negative, or not strictly increasing)."""


class AuditKindError(TimeSeriesDBError):
    """Unknown audit kind passed to the audit event builder."""


def _check_str(value: Any, exc: type, what: str, max_len: int) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise exc(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise exc(f"{what} must not be empty")
    if len(value) > max_len:
        raise exc(f"{what} too long (>{max_len} chars)")
    return value


def _check_measurement(measurement: Any) -> str:
    return _check_str(
        measurement, BadMeasurementError, "measurement", _MAX_MEASUREMENT_LEN
    )


def _check_tags(tags: Any) -> Tuple[Tuple[str, str], ...]:
    if tags is None:
        return ()
    if isinstance(tags, bool) or not isinstance(tags, Mapping):
        raise BadTagError(f"tags must be a mapping, got {type(tags).__name__}")
    if not tags:
        return ()
    out = []
    for k, v in tags.items():
        key = _check_str(k, BadTagError, "tag key", _MAX_TAG_KEY_LEN)
        val = _check_str(v, BadTagError, "tag value", _MAX_TAG_VALUE_LEN)
        out.append((key, val))
    out.sort()
    return tuple(out)


def _check_fields(fields: Any) -> Tuple[Tuple[str, Tuple[str, str]], ...]:
    if isinstance(fields, bool) or not isinstance(fields, Mapping):
        raise BadFieldError(f"fields must be a mapping, got {type(fields).__name__}")
    if not fields:
        raise BadFieldError("fields must not be empty")
    out = []
    for k, v in fields.items():
        key = _check_str(k, BadFieldError, "field key", _MAX_FIELD_KEY_LEN)
        out.append((key, _canon_value(v)))
    out.sort(key=lambda kv: kv[0])
    return tuple(out)


def _canon_value(value: Any) -> Tuple[str, str]:
    """Type-tag a field value so digests never conflate types."""
    if isinstance(value, bool):
        return ("b", "1" if value else "0")
    if isinstance(value, int):
        if abs(value) >= _MAX_SAFE_INT:
            raise BadFieldError(f"int field value out of safe range: {value}")
        return ("i", str(value))
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadFieldError("float field value must be finite")
        return ("f", repr(value))
    if isinstance(value, str):
        if len(value) > _MAX_STRING_FIELD_LEN:
            raise BadFieldError(
                f"string field value too long (>{_MAX_STRING_FIELD_LEN} chars)"
            )
        return ("s", value)
    raise BadFieldError(
        f"field value must be int/float/str/bool, got {type(value).__name__}"
    )


def _check_timestamp(timestamp: Any) -> int:
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise BadTimestampError(
            f"timestamp must be an int, got {type(timestamp).__name__}"
        )
    if timestamp < 0:
        raise BadTimestampError(f"timestamp must be >= 0, got {timestamp}")
    return timestamp


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"seq must be >= 0, got {seq}")
    return seq


def _digest(parts: Tuple[str, ...]) -> str:
    body = "\x1f".join(parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class PointRecord:
    """One booked time-series point."""

    measurement: str
    tags: Tuple[Tuple[str, str], ...]
    fields: Tuple[Tuple[str, Tuple[str, str]], ...]
    timestamp: int
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin from the record's contents."""
        parts = ["measurement", self.measurement, "ts", str(self.timestamp)]
        for k, v in self.tags:
            parts += ["tag", k, v]
        for k, (t, s) in self.fields:
            parts += ["field", k, t, s]
        return self.digest == _digest(tuple(parts))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "measurement": self.measurement,
            "tags": [list(kv) for kv in self.tags],
            "fields": [[k, list(ts)] for k, ts in self.fields],
            "timestamp": self.timestamp,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class PointView:
    """A point as returned by query (public read shape)."""

    measurement: str
    tags: Tuple[Tuple[str, str], ...]
    fields: Tuple[Tuple[str, Tuple[str, str]], ...]
    timestamp: int
    digest: str


@dataclass(frozen=True)
class QueryReport:
    """Result of a query: pure data, never an error on empty matches."""

    measurement: str
    tag_filter: Tuple[Tuple[str, str], ...]
    count: int
    points: Tuple[PointView, ...]
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "measurement": self.measurement,
            "count": self.count,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class BucketRecord:
    """One computed downsample bucket."""

    bucket_start: int
    field: str
    count: int
    result: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "bucket_start": self.bucket_start,
            "field": self.field,
            "count": self.count,
            "result": self.result,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DownsampleRecord:
    """One booked downsample (rollup) pass."""

    measurement: str
    window_seqs: int
    aggregator: str
    bucket_count: int
    buckets: Tuple[BucketRecord, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        parts = [
            "downsample",
            self.measurement,
            str(self.window_seqs),
            self.aggregator,
            str(self.seq),
        ]
        for b in self.buckets:
            parts += [str(b.bucket_start), b.field, str(b.count), b.result]
        return self.digest == _digest(tuple(parts))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "measurement": self.measurement,
            "window_seqs": self.window_seqs,
            "aggregator": self.aggregator,
            "bucket_count": self.bucket_count,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class SeriesReport:
    """Tag-set cardinality for one measurement."""

    measurement: str
    series_count: int
    tag_keys: Tuple[str, ...]
    point_count: int


@dataclass(frozen=True)
class StatsReport:
    """Pure read view of ledger counters."""

    measurements: int
    points_total: int
    writes: int
    downsamples: int
    rejected: int


class TimeSeriesDB:
    """InfluxDB-shaped write/query/downsample bookkeeping ledger."""

    def __init__(self) -> None:
        self._points: Dict[str, list] = {}
        self._writes = 0
        self._downsamples = 0
        self._rejected = 0
        self._last_seq = -1
        self._audit: list = []

    # -- internal helpers ---------------------------------------------------

    def _view_seq(self, seq: Any) -> int:
        return _check_seq(seq)

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase; got {seq} after {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _fail(self, seq: int, exc: TimeSeriesDBError, kind: str, **detail: Any) -> None:
        self._rejected += 1
        self._audit.append(
            time_series_db_audit_event("rejected", seq, error=type(exc).__name__,
                                       **detail)
        )
        raise exc

    def _matches(self, point: PointRecord, tag_filter: Tuple[Tuple[str, str], ...],
                 start: Optional[int], stop: Optional[int]) -> bool:
        ptag = dict(point.tags)
        for k, v in tag_filter:
            if ptag.get(k) != v:
                return False
        if start is not None and point.timestamp < start:
            return False
        if stop is not None and point.timestamp >= stop:
            return False
        return True

    # -- mutations ----------------------------------------------------------

    def write(self, measurement: str, tags: Optional[Mapping[str, str]],
              fields: Mapping[str, Any], seq: int,
              timestamp: Optional[int] = None) -> PointRecord:
        """Book one time-series point; measurements auto-register."""
        seq = self._claim(seq)
        try:
            m = _check_measurement(measurement)
            t = _check_tags(tags)
            f = _check_fields(fields)
            ts = _check_timestamp(timestamp if timestamp is not None else seq)
        except TimeSeriesDBError as exc:
            self._fail(seq, exc, "written", measurement=str(measurement))
        parts = ["measurement", m, "ts", str(ts)]
        for k, v in t:
            parts += ["tag", k, v]
        for k, (typ, s) in f:
            parts += ["field", k, typ, s]
        record = PointRecord(m, t, f, ts, seq, _digest(tuple(parts)))
        self._points.setdefault(m, []).append(record)
        self._writes += 1
        self._audit.append(
            time_series_db_audit_event(
                "written", seq, measurement=m, digest=record.digest,
                tag_count=len(t), field_count=len(f), timestamp=ts,
            )
        )
        return record

    def downsample(self, measurement: str, seq: int, window_seqs: int,
                   aggregator: str = "mean",
                   tags: Optional[Mapping[str, str]] = None,
                   start: Optional[int] = None,
                   stop: Optional[int] = None) -> DownsampleRecord:
        """Book one rollup pass over a measurement's points."""
        seq = self._claim(seq)
        try:
            m = _check_measurement(measurement)
            if isinstance(window_seqs, bool) or not isinstance(window_seqs, int):
                raise BadWindowError(
                    f"window_seqs must be an int, got {type(window_seqs).__name__}"
                )
            if window_seqs <= 0:
                raise BadWindowError(f"window_seqs must be > 0, got {window_seqs}")
            if aggregator not in AGGREGATORS:
                raise BadAggregatorError(
                    f"unknown aggregator {aggregator!r}; allowed: {list(AGGREGATORS)}"
                )
            t = _check_tags(tags)
            if start is not None:
                _check_timestamp(start)
            if stop is not None:
                _check_timestamp(stop)
        except TimeSeriesDBError as exc:
            self._fail(seq, exc, "downsampled", measurement=str(measurement))

        points = [p for p in self._points.get(m, ())
                  if self._matches(p, t, start, stop)]

        # Bucket: (bucket_start, field_name) -> list of (value_type, value).
        buckets: Dict[Tuple[int, str], list] = {}
        point_count: Dict[int, int] = {}
        for p in points:
            lo = (p.timestamp // window_seqs) * window_seqs
            point_count[lo] = point_count.get(lo, 0) + 1
            if aggregator == "count":
                continue
            for fname, (typ, sval) in p.fields:
                if typ not in ("i", "f"):
                    continue
                val = int(sval) if typ == "i" else float(sval)
                buckets.setdefault((lo, fname), []).append((typ, val))

        records: list = []
        for (lo, fname), vals in sorted(buckets.items()):
            if aggregator == "mean":
                total = sum(v for _, v in vals)
                result = f"{total}/{len(vals)}"
            elif aggregator == "sum":
                total = sum(v for _, v in vals)
                result = str(int(total)) if all(t == "i" for t, _ in vals) else repr(total)
            elif aggregator == "min":
                result = repr(min(v for _, v in vals))
            else:  # max
                result = repr(max(v for _, v in vals))
            digest = _digest(("bucket", str(lo), fname, str(len(vals)), result))
            records.append(BucketRecord(lo, fname, len(vals), result, digest))

        if aggregator == "count":
            for lo in sorted(point_count):
                digest = _digest(("bucket", str(lo), "*", str(point_count[lo])))
                records.append(
                    BucketRecord(lo, "*", point_count[lo],
                                 str(point_count[lo]), digest)
                )

        records.sort(key=lambda b: (b.bucket_start, b.field))
        parts = ["downsample", m, str(window_seqs), aggregator, str(seq)]
        for b in records:
            parts += [str(b.bucket_start), b.field, str(b.count), b.result]
        record = DownsampleRecord(m, window_seqs, aggregator, len(records),
                                  tuple(records), seq, _digest(tuple(parts)))
        self._downsamples += 1
        self._audit.append(
            time_series_db_audit_event(
                "downsampled", seq, measurement=m, aggregator=aggregator,
                window_seqs=window_seqs, bucket_count=len(records),
                digest=record.digest,
            )
        )
        return record

    # -- pure read views ----------------------------------------------------

    def query(self, measurement: str, seq: int,
              tags: Optional[Mapping[str, str]] = None,
              start: Optional[int] = None,
              stop: Optional[int] = None) -> QueryReport:
        """Query points as data; empty match is data, never raised."""
        self._view_seq(seq)
        m = _check_measurement(measurement)
        t = _check_tags(tags)
        if start is not None:
            _check_timestamp(start)
        if stop is not None:
            _check_timestamp(stop)
        views = tuple(
            PointView(p.measurement, p.tags, p.fields, p.timestamp, p.digest)
            for p in self._points.get(m, ())
            if self._matches(p, t, start, stop)
        )
        parts = ["query", m, str(len(views))]
        for v in views:
            parts.append(v.digest)
        return QueryReport(m, t, len(views), views, _digest(tuple(parts)))

    def measurement_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted measurement names known to this ledger."""
        self._view_seq(seq)
        return tuple(sorted(self._points))

    def series(self, measurement: str, seq: int) -> SeriesReport:
        """Tag-set cardinality for one measurement."""
        self._view_seq(seq)
        m = _check_measurement(measurement)
        points = self._points.get(m, ())
        tag_sets = {p.tags for p in points}
        keys = sorted({k for p in points for k, _ in p.tags})
        return SeriesReport(m, len(tag_sets), tuple(keys), len(points))

    def stats(self, seq: int) -> StatsReport:
        """Pure read view of ledger counters."""
        self._view_seq(seq)
        return StatsReport(
            len(self._points),
            sum(len(v) for v in self._points.values()),
            self._writes,
            self._downsamples,
            self._rejected,
        )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(self._audit)


def time_series_db_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for a time-series event."""
    allowed = {"written", "downsampled", "rejected"}
    if kind not in allowed:
        raise AuditKindError(f"unknown audit kind {kind!r}; allowed: {sorted(allowed)}")
    _check_seq(seq)
    for banned in ("value", "fields", "tags", "payload", "raw"):
        if banned in fields:
            raise TimeSeriesDBError(
                f"raw {banned} values are never logged; pass digests"
            )
    record = {
        "schema": AUDIT_SCHEMA,
        "kind": f"time-series-db.{kind}",
        "module": TIME_SERIES_DB_VERSION,
        "seq": seq,
    }
    record.update(fields)
    return record


def main() -> None:
    """Self-check: write, query, downsample, pins, audit."""
    db = TimeSeriesDB()
    p1 = db.write("cpu", {"host": "a"}, {"usage": 10, "note": "ok"}, 1, timestamp=10)
    p2 = db.write("cpu", {"host": "b"}, {"usage": 30}, 2, timestamp=140)
    assert p1.verify() and p2.verify()
    q = db.query("cpu", 3)
    assert q.count == 2, q.count
    qf = db.query("cpu", 3, tags={"host": "a"})
    assert qf.count == 1 and qf.points[0].digest == p1.digest
    qw = db.query("cpu", 3, start=120)
    assert qw.count == 1, qw.count
    ds = db.downsample("cpu", 4, 100, aggregator="mean")
    assert ds.bucket_count == 2, ds.bucket_count
    assert ds.verify()
    bucket = ds.buckets[0]
    assert bucket.field == "usage" and bucket.result == "10/1", bucket
    ds2 = db.downsample("cpu", 5, 1000, aggregator="sum")
    assert ds2.buckets[0].result == "40", ds2.buckets[0]
    kinds = {r["kind"] for r in db.audit_log()}
    assert "time-series-db.written" in kinds
    assert "time-series-db.downsampled" in kinds
    s = db.stats(6)
    assert s.points_total == 2 and s.writes == 2 and s.downsamples == 2
    print("time-series-db OK: write, query, downsample, pins, audit")


if __name__ == "__main__":
    main()
