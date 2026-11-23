"""Metrics collection — simulated StatsD-style metric bookkeeping (thirty-fourth batch).

Research note (metrics collection literature): Prometheus and StatsD are
the two dominant host-side metric collection contracts. Both model three
instrument types:

* **Counters** — monotonically increasing cumulative totals (requests
  served, bytes sent). Negative increments are refused client-side;
  a decreasing counter breaks ``rate()``/``increase()`` queries.
* **Gauges** — free values that move up and down (queue depth,
  temperature, connections open).
* **Histograms** — value distributions as cumulative bucket counts plus
  ``_sum``/``_count`` (request latencies, payload sizes). Buckets must
  be declared in strictly increasing order.

StatsD adds a collection discipline that Prometheus' pull model lacks:
the host **flushes** aggregated metrics on a cadence — counters reset
to zero after a flush (the flush reports the *delta*), gauges are
re-reported, histogram buckets are re-aggregated. This module takes the
intersection for a single-host deterministic ledger:

* **Explicit instruments**: ``define_counter`` / ``define_gauge`` /
  ``define_histogram`` book a metric definition (pinned name, type,
  optional tag-key vocabulary). No HTTP endpoint, no UDP socket, no
  wall-clock — every mutation takes a caller-supplied logical seq.
* **Host-reported samples**: ``counter`` / ``gauge`` / ``histogram``
  book host-reported values as data (GIGO). Counters refuse negative
  increments; histograms refuse negative observations.
* **Deterministic rollups**: ``aggregate`` is a pure view returning a
  frozen aggregate (count, sum, min, max, mean, and p50/p95/p99 for
  histograms via nearest-rank on cumulative buckets).
* **Flush semantics**: ``flush`` emits a frozen per-instrument
  aggregate report, then resets collection buffers — counters to zero,
  histogram buckets emptied, gauges retained (StatsD-faithful).

Relationship to the sibling ``prom_metrics`` module: that module owns
the *Prometheus registry + exposition text* contract (cumulative
series, ``scrape()`` text format). This module owns the *StatsD-style
collection + flush* contract (per-cadence deltas, deterministic
rollups). They are complementary, not overlapping.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool/
negative/rewind refused), RLock-guarded, fail-closed taxonomy,
stdlib-only (``canonical_json`` sibling helper behind the standard
try/except fallback), sha256 digest pins over type-tagged canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* metric operations
deterministically. It collects no real telemetry, samples no
processes, and cannot prove a reported value was measured — the host
declares every sample. An aggregate means "the host reported these
values", never "the system behaved this way". Pair with a real
exporter/agent for production.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
METRICS_COLLECTION_VERSION = "metrics-collection.v1"

#: Schema pin carried by records and audit events.
METRICS_COLLECTION_SCHEMA = "northstar.metrics-collection.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned instrument types.
TYPE_COUNTER = "counter"
TYPE_GAUGE = "gauge"
TYPE_HISTOGRAM = "histogram"
METRIC_TYPES = (TYPE_COUNTER, TYPE_GAUGE, TYPE_HISTOGRAM)

#: Prometheus-compatible metric name grammar (also valid for StatsD).
_NAME_RE = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_.:]*")

#: StatsD tag key grammar.
_TAG_KEY_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_.]*")

#: Tag values may not carry StatsD field separators.
_TAG_VALUE_BAD = (",", ":", "|", "#", " ")

#: Audit event kinds.
KIND_METRIC_DEFINED = "metric.defined"
KIND_COLLECTED = "metric.collected"
KIND_FLUSHED = "metric.flushed"
KIND_REJECTED = "metric.rejected"
_KINDS = (KIND_METRIC_DEFINED, KIND_COLLECTED, KIND_FLUSHED, KIND_REJECTED)

#: Keys that may never cross the audit boundary (raw sample data).
_BANNED_AUDIT_KEYS = {"samples", "values", "observations"}

#: Max magnitude for a finite value (avoids silent >2^53 precision loss).
_MAX_SAFE = float(2**53)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class MetricsCollectionError(Exception):
    """Base error for metrics-collection."""


class BadMetricError(MetricsCollectionError):
    """Metric name/shape invalid."""


class DuplicateMetricError(MetricsCollectionError):
    """Metric name already defined."""


class UnknownMetricError(MetricsCollectionError):
    """Metric name not defined."""


class MetricTypeConflictError(MetricsCollectionError):
    """Instrument already defined with a different type."""


class BadValueError(MetricsCollectionError):
    """Sampled value invalid (bool/NaN/inf/unsafe-int/negative)."""


class CounterDecreaseError(MetricsCollectionError):
    """Negative increment on a counter."""


class BadBucketError(MetricsCollectionError):
    """Histogram bucket list invalid."""


class BadTagError(MetricsCollectionError):
    """Tag key/value invalid or tag-set mismatch."""


class SeqOrderError(MetricsCollectionError):
    """Caller seq did not strictly increase."""


class AuditKindError(MetricsCollectionError):
    """Unknown audit kind."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_name(name: Any, what: str = "name") -> str:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise BadMetricError(
            f"{what} must match [a-zA-Z_:][a-zA-Z0-9_.:]*, got {name!r}"
        )
    if len(name) > 128:
        raise BadMetricError(f"{what} too long (max 128 chars)")
    return name


def _check_tags(tags: Any, declared: Optional[Sequence[str]]) -> Tuple[Tuple[str, str], ...]:
    if tags is None:
        tags = ()
    if isinstance(tags, Mapping):
        items = list(tags.items())
    elif isinstance(tags, (list, tuple)):
        items = list(tags)
    else:
        raise BadTagError(f"tags must be a mapping or list of pairs, got {type(tags).__name__}")
    pairs: List[Tuple[str, str]] = []
    seen: set = set()
    for item in items:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise BadTagError(f"tag must be a (key, value) pair, got {item!r}")
        key, value = item
        if not isinstance(key, str) or not _TAG_KEY_RE.fullmatch(key):
            raise BadTagError(f"bad tag key: {key!r}")
        if not isinstance(value, str) or not value or any(c in value for c in _TAG_VALUE_BAD):
            raise BadTagError(f"bad tag value: {value!r}")
        if key in seen:
            raise BadTagError(f"duplicate tag key: {key!r}")
        seen.add(key)
        pairs.append((key, value))
    if declared is not None:
        declared_set = set(declared)
        if seen != declared_set:
            raise BadTagError(
                f"tag set {sorted(seen)} does not match declared {sorted(declared_set)}"
            )
    return tuple(sorted(pairs))


def _check_number(value: Any, what: str, allow_negative: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadValueError(f"{what} must be a number, got {value!r}")
    fval = float(value)
    if not math.isfinite(fval):
        raise BadValueError(f"{what} must be finite, got {value!r}")
    if abs(fval) >= _MAX_SAFE:
        raise BadValueError(f"{what} exceeds safe integer range")
    if not allow_negative and fval < 0:
        raise BadValueError(f"{what} must be non-negative, got {value!r}")
    return fval


def _check_buckets(buckets: Any) -> Tuple[float, ...]:
    if not isinstance(buckets, (list, tuple)) or len(buckets) == 0:
        raise BadBucketError("buckets must be a non-empty list")
    bounds: List[float] = []
    for bound in buckets:
        try:
            bval = _check_number(bound, "bucket bound", allow_negative=False)
        except BadValueError as exc:
            raise BadBucketError(str(exc)) from exc
        if bval <= 0:
            raise BadBucketError(f"bucket bound must be positive, got {bound!r}")
        bounds.append(bval)
    for prev, cur in zip(bounds, bounds[1:]):
        if not cur > prev:
            raise BadBucketError("buckets must be strictly increasing")
    return tuple(bounds)


def _canonical(obj: Any) -> bytes:
    if _cj is not None and hasattr(_cj, "jcs_dumps"):
        return _cj.jcs_dumps(obj).encode("utf-8")  # type: ignore[no-any-return]
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(parts: Sequence[Any], seed: str) -> str:
    mac = hmac.new(
        ("metrics-collection:" + seed).encode("utf-8"),
        _canonical(["metrics-collection", *parts]),
        hashlib.sha256,
    ).hexdigest()
    return f"sha256:{mac}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricDefinition:
    """One pinned instrument definition (frozen)."""

    name: str
    metric_type: str
    tag_keys: Tuple[str, ...]
    description: str
    buckets: Tuple[float, ...]
    digest: str
    schema: str = METRICS_COLLECTION_SCHEMA

    def verify(self, seed: str) -> bool:
        return self.digest == _pin(
            ["metric-definition", self.name, self.metric_type,
             list(self.tag_keys), self.description,
             [repr(b) for b in self.buckets]],
            seed,
        )


@dataclass(frozen=True)
class SampleRecord:
    """One booked sample (frozen)."""

    sample_id: str
    name: str
    metric_type: str
    tags: Tuple[Tuple[str, str], ...]
    value: float
    seq: int
    digest: str
    schema: str = METRICS_COLLECTION_SCHEMA

    def verify(self, seed: str) -> bool:
        return self.digest == _pin(
            ["sample", self.sample_id, self.name, self.metric_type,
             [list(t) for t in self.tags], repr(self.value), self.seq],
            seed,
        )


@dataclass(frozen=True)
class HistogramBucket:
    """One cumulative bucket count (frozen)."""

    upper_bound: float
    cumulative_count: int


@dataclass(frozen=True)
class Aggregate:
    """A deterministic rollup over one series (frozen).

    For counters: ``count`` = increments booked, ``sum`` = cumulative
    total, ``min``/``max`` = increment min/max, ``mean`` = mean
    increment. For gauges: the last reported value (``count`` = 1 when
    a value was set). For histograms: ``count``/``sum``/``min``/``max``/
    ``mean`` over observations plus ``p50``/``p95``/``p99`` (nearest-
    rank quantiles on cumulative buckets) and per-bucket cumulative
    counts. Empty instruments roll up to zeros/``None`` — verdicts are
    data, never errors.
    """

    name: str
    metric_type: str
    tags: Tuple[Tuple[str, str], ...]
    count: int
    sum: float
    min: Optional[float]
    max: Optional[float]
    mean: Optional[float]
    p50: Optional[float]
    p95: Optional[float]
    p99: Optional[float]
    buckets: Tuple[HistogramBucket, ...]
    digest: str
    schema: str = METRICS_COLLECTION_SCHEMA

    def verify(self, seed: str) -> bool:
        return self.digest == _pin(
            ["aggregate", self.name, self.metric_type,
             [list(t) for t in self.tags], self.count, repr(self.sum),
             None if self.min is None else repr(self.min),
             None if self.max is None else repr(self.max),
             None if self.mean is None else repr(self.mean),
             None if self.p50 is None else repr(self.p50),
             None if self.p95 is None else repr(self.p95),
             None if self.p99 is None else repr(self.p99),
             [[repr(b.upper_bound), b.cumulative_count] for b in self.buckets]],
            seed,
        )


@dataclass(frozen=True)
class FlushReport:
    """One flush: per-instrument aggregates + buffer reset (frozen).

    Counters reset to zero, histogram buckets empty, gauges retained —
    StatsD-faithful flush semantics.
    """

    flush_seq: int
    aggregates: Tuple[Aggregate, ...]
    digest: str
    schema: str = METRICS_COLLECTION_SCHEMA

    def verify(self, seed: str) -> bool:
        return self.digest == _pin(
            ["flush", self.flush_seq,
             [a.digest for a in self.aggregates]],
            seed,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def metrics_collection_audit_event(
    kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the metrics-collection module.

    Raw sample values never cross the audit boundary — only names,
    types, ids, counts, sums, and digest pins.
    """
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    detail = dict(detail) if detail else {}
    if any(k in detail for k in _BANNED_AUDIT_KEYS):
        raise MetricsCollectionError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": METRICS_COLLECTION_VERSION,
        "detail": detail,
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class MetricsCollection:
    """Deterministic StatsD-style metric collection ledger.

    All mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume
    their seq (fail-closed ledger position).
    """

    def __init__(self, seed: str = "default") -> None:
        if not isinstance(seed, str) or not seed:
            raise MetricsCollectionError("seed must be a non-empty string")
        self._seed = seed
        self._lock = threading.RLock()
        self._defs: Dict[str, MetricDefinition] = {}
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._counter_samples: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], int] = {}
        self._counter_minmax: Dict[
            Tuple[str, Tuple[Tuple[str, str], ...]], Tuple[float, float]
        ] = {}
        self._gauges: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._histograms: Dict[
            Tuple[str, Tuple[Tuple[str, str], ...]], "_HistState"
        ] = {}
        self._buckets: Dict[str, Tuple[float, ...]] = {}
        self._next_seq = 0
        self._sample_count = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals --------------------------------------------------------

    def _pin(self, parts: Sequence[Any]) -> str:
        return _pin(parts, self._seed)

    def _next(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._next_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (next > {self._next_seq})"
            )
        self._next_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(
            metrics_collection_audit_event(kind, seq, detail)
        )

    def _reject(self, seq: int, reason: str) -> None:
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _definition(self, name: str, expected_type: str) -> MetricDefinition:
        definition = self._defs.get(name)
        if definition is None:
            raise UnknownMetricError(f"metric not defined: {name!r}")
        if definition.metric_type != expected_type:
            raise MetricTypeConflictError(
                f"{name!r} is a {definition.metric_type}, not a {expected_type}"
            )
        return definition

    # -- definitions ------------------------------------------------------

    def define_counter(
        self,
        name: str,
        seq: int,
        description: str = "",
        tag_keys: Sequence[str] = (),
    ) -> MetricDefinition:
        """Book a counter instrument."""
        return self._define(TYPE_COUNTER, name, seq, description, tag_keys)

    def define_gauge(
        self,
        name: str,
        seq: int,
        description: str = "",
        tag_keys: Sequence[str] = (),
    ) -> MetricDefinition:
        """Book a gauge instrument."""
        return self._define(TYPE_GAUGE, name, seq, description, tag_keys)

    def define_histogram(
        self,
        name: str,
        seq: int,
        buckets: Sequence[Any],
        description: str = "",
        tag_keys: Sequence[str] = (),
    ) -> MetricDefinition:
        """Book a histogram instrument with pinned bucket bounds."""
        with self._lock:
            try:
                seq = self._next(seq)
                _check_name(name)
                bounds = _check_buckets(buckets)
                if name in self._defs:
                    raise DuplicateMetricError(f"metric already defined: {name!r}")
                keys = self._declare_tag_keys(tag_keys)
                digest = self._pin(
                    ["metric-definition", name, TYPE_HISTOGRAM,
                     list(keys), description, [repr(b) for b in bounds]]
                )
                definition = MetricDefinition(
                    name=name,
                    metric_type=TYPE_HISTOGRAM,
                    tag_keys=keys,
                    description=description,
                    buckets=bounds,
                    digest=digest,
                )
                self._defs[name] = definition
                self._buckets[name] = bounds
                self._emit(
                    KIND_METRIC_DEFINED, seq, name=name,
                    metric_type=TYPE_HISTOGRAM, digest=digest,
                )
                return definition
            except MetricsCollectionError as exc:
                self._reject(seq, str(exc))
                raise

    def _declare_tag_keys(self, tag_keys: Sequence[str]) -> Tuple[str, ...]:
        if not isinstance(tag_keys, (list, tuple)):
            raise BadTagError("tag_keys must be a list/tuple of strings")
        keys: List[str] = []
        for key in tag_keys:
            if not isinstance(key, str) or not _TAG_KEY_RE.fullmatch(key):
                raise BadTagError(f"bad tag key: {key!r}")
            if key in keys:
                raise BadTagError(f"duplicate tag key: {key!r}")
            keys.append(key)
        return tuple(sorted(keys))

    def _define(
        self,
        metric_type: str,
        name: str,
        seq: int,
        description: str,
        tag_keys: Sequence[str],
    ) -> MetricDefinition:
        with self._lock:
            try:
                seq = self._next(seq)
                _check_name(name)
                if name in self._defs:
                    raise DuplicateMetricError(f"metric already defined: {name!r}")
                if not isinstance(description, str) or len(description) > 256:
                    raise BadMetricError("description must be a string <= 256 chars")
                keys = self._declare_tag_keys(tag_keys)
                digest = self._pin(
                    ["metric-definition", name, metric_type,
                     list(keys), description, []]
                )
                definition = MetricDefinition(
                    name=name,
                    metric_type=metric_type,
                    tag_keys=keys,
                    description=description,
                    buckets=(),
                    digest=digest,
                )
                self._defs[name] = definition
                self._emit(
                    KIND_METRIC_DEFINED, seq, name=name,
                    metric_type=metric_type, digest=digest,
                )
                return definition
            except MetricsCollectionError as exc:
                self._reject(seq, str(exc))
                raise

    # -- collection -------------------------------------------------------

    def counter(
        self,
        name: str,
        amount: Any,
        seq: int,
        tags: Optional[Any] = None,
    ) -> SampleRecord:
        """Book a counter increment (non-negative; negative refused)."""
        with self._lock:
            try:
                seq = self._next(seq)
                definition = self._definition(name, TYPE_COUNTER)
                fval = _check_number(amount, "amount", allow_negative=True)
                if fval < 0:
                    raise CounterDecreaseError(
                        f"counter increment must be non-negative, got {amount!r}"
                    )
                tkey = _check_tags(tags, definition.tag_keys)
                key = (name, tkey)
                self._counters[key] = self._counters.get(key, 0.0) + fval
                self._counter_samples[key] = self._counter_samples.get(key, 0) + 1
                lo, hi = self._counter_minmax.get(key, (fval, fval))
                self._counter_minmax[key] = (min(lo, fval), max(hi, fval))
                return self._book_sample(name, TYPE_COUNTER, tkey, fval, seq)
            except MetricsCollectionError as exc:
                self._reject(seq, str(exc))
                raise

    def gauge(
        self,
        name: str,
        value: Any,
        seq: int,
        tags: Optional[Any] = None,
    ) -> SampleRecord:
        """Book a gauge set (any finite value, up or down)."""
        with self._lock:
            try:
                seq = self._next(seq)
                definition = self._definition(name, TYPE_GAUGE)
                fval = _check_number(value, "value", allow_negative=True)
                tkey = _check_tags(tags, definition.tag_keys)
                key = (name, tkey)
                self._gauges[key] = fval
                return self._book_sample(name, TYPE_GAUGE, tkey, fval, seq)
            except MetricsCollectionError as exc:
                self._reject(seq, str(exc))
                raise

    def histogram(
        self,
        name: str,
        value: Any,
        seq: int,
        tags: Optional[Any] = None,
    ) -> SampleRecord:
        """Book a histogram observation (non-negative)."""
        with self._lock:
            try:
                seq = self._next(seq)
                definition = self._definition(name, TYPE_HISTOGRAM)
                fval = _check_number(value, "value", allow_negative=False)
                tkey = _check_tags(tags, definition.tag_keys)
                key = (name, tkey)
                state = self._histograms.get(key)
                if state is None:
                    bounds = self._buckets[name]
                    state = _HistState(bucket_counts=[0] * len(bounds))
                    self._histograms[key] = state
                bounds = self._buckets[name]
                for i, bound in enumerate(bounds):
                    if fval <= bound:
                        state.bucket_counts[i] += 1
                state.count += 1
                state.sum += fval
                if state.min is None or fval < state.min:
                    state.min = fval
                if state.max is None or fval > state.max:
                    state.max = fval
                state.values.append(fval)
                return self._book_sample(name, TYPE_HISTOGRAM, tkey, fval, seq)
            except MetricsCollectionError as exc:
                self._reject(seq, str(exc))
                raise

    def _book_sample(
        self,
        name: str,
        metric_type: str,
        tags: Tuple[Tuple[str, str], ...],
        value: float,
        seq: int,
    ) -> SampleRecord:
        self._sample_count += 1
        sample_id = f"smp-{self._sample_count}"
        digest = self._pin(
            ["sample", sample_id, name, metric_type,
             [list(t) for t in tags], repr(value), seq]
        )
        record = SampleRecord(
            sample_id=sample_id,
            name=name,
            metric_type=metric_type,
            tags=tags,
            value=value,
            seq=seq,
            digest=digest,
        )
        self._emit(
            KIND_COLLECTED, seq, name=name, metric_type=metric_type,
            sample_id=sample_id, digest=digest,
        )
        return record

    # -- views ------------------------------------------------------------

    def aggregate(
        self,
        name: str,
        seq: int,
        tags: Optional[Any] = None,
    ) -> Aggregate:
        """Pure view: deterministic rollup over one series.

        Validates seq shape but consumes nothing and writes no audit row.
        """
        with self._lock:
            _check_seq(seq)
            definition = self._defs.get(name)
            if definition is None:
                raise UnknownMetricError(f"metric not defined: {name!r}")
            tkey = _check_tags(tags, definition.tag_keys)
            key = (name, tkey)
            if definition.metric_type == TYPE_COUNTER:
                value = self._counters.get(key, 0.0)
                samples = self._counter_samples.get(key, 0)
                if samples == 0:
                    return self._empty_aggregate(name, TYPE_COUNTER, tkey)
                lo, hi = self._counter_minmax[key]
                return self._rollup_scalar(
                    name, TYPE_COUNTER, tkey, samples, value, lo, hi
                )
            if definition.metric_type == TYPE_GAUGE:
                if key not in self._gauges:
                    return self._empty_aggregate(name, TYPE_GAUGE, tkey)
                value = self._gauges[key]
                return self._rollup_scalar(name, TYPE_GAUGE, tkey, 1, value, value, value)
            state = self._histograms.get(key)
            if state is None:
                return self._empty_histogram(name, tkey)
            return self._rollup_histogram(name, tkey, state)

    def series(self, seq: int) -> Tuple[str, ...]:
        """Pure view: sorted defined metric names."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._defs))

    def definition(self, name: str, seq: int) -> MetricDefinition:
        """Pure view: the definition record for one metric."""
        with self._lock:
            _check_seq(seq)
            definition = self._defs.get(name)
            if definition is None:
                raise UnknownMetricError(f"metric not defined: {name!r}")
            return definition

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure view: counts of definitions/samples per type."""
        with self._lock:
            _check_seq(seq)
            types: Dict[str, int] = {t: 0 for t in METRIC_TYPES}
            for definition in self._defs.values():
                types[definition.metric_type] += 1
            return {
                "metrics": types,
                "series": len(self._counters) + len(self._gauges) + len(self._histograms),
                "samples": self._sample_count,
                "schema": METRICS_COLLECTION_SCHEMA,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure view: the audit ledger."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)

    # -- rollups ----------------------------------------------------------

    def _empty_aggregate(
        self, name: str, metric_type: str,
        tags: Tuple[Tuple[str, str], ...],
    ) -> Aggregate:
        digest = self._pin(
            ["aggregate", name, metric_type, [list(t) for t in tags],
             0, repr(0.0), None, None, None, None, None, None, []]
        )
        return Aggregate(
            name=name, metric_type=metric_type, tags=tags,
            count=0, sum=0.0, min=None, max=None, mean=None,
            p50=None, p95=None, p99=None, buckets=(),
            digest=digest,
        )

    def _rollup_scalar(
        self, name: str, metric_type: str,
        tags: Tuple[Tuple[str, str], ...],
        count: int, total: float, lo: float, hi: float,
    ) -> Aggregate:
        mean = total / count if count else None
        digest = self._pin(
            ["aggregate", name, metric_type, [list(t) for t in tags],
             count, repr(total), repr(lo), repr(hi),
             None if mean is None else repr(mean),
             None, None, None, []]
        )
        return Aggregate(
            name=name, metric_type=metric_type, tags=tags,
            count=count, sum=total, min=lo, max=hi, mean=mean,
            p50=None, p95=None, p99=None, buckets=(),
            digest=digest,
        )

    def _empty_histogram(
        self, name: str,
        tags: Tuple[Tuple[str, str], ...],
    ) -> Aggregate:
        bounds = self._buckets[name]
        buckets = tuple(
            HistogramBucket(upper_bound=b, cumulative_count=0) for b in bounds
        )
        digest = self._pin(
            ["aggregate", name, TYPE_HISTOGRAM, [list(t) for t in tags],
             0, repr(0.0), None, None, None, None, None, None,
             [[repr(b.upper_bound), b.cumulative_count] for b in buckets]]
        )
        return Aggregate(
            name=name, metric_type=TYPE_HISTOGRAM, tags=tags,
            count=0, sum=0.0, min=None, max=None, mean=None,
            p50=None, p95=None, p99=None, buckets=buckets,
            digest=digest,
        )

    def _rollup_histogram(
        self, name: str,
        tags: Tuple[Tuple[str, str], ...],
        state: "_HistState",
    ) -> Aggregate:
        bounds = self._buckets[name]
        buckets = tuple(
            HistogramBucket(upper_bound=b, cumulative_count=c)
            for b, c in zip(bounds, state.bucket_counts)
        )
        mean = state.sum / state.count if state.count else None
        p50 = self._quantile(buckets, state.count, 0.50)
        p95 = self._quantile(buckets, state.count, 0.95)
        p99 = self._quantile(buckets, state.count, 0.99)
        digest = self._pin(
            ["aggregate", name, TYPE_HISTOGRAM, [list(t) for t in tags],
             state.count, repr(state.sum),
             None if state.min is None else repr(state.min),
             None if state.max is None else repr(state.max),
             None if mean is None else repr(mean),
             None if p50 is None else repr(p50),
             None if p95 is None else repr(p95),
             None if p99 is None else repr(p99),
             [[repr(b.upper_bound), b.cumulative_count] for b in buckets]]
        )
        return Aggregate(
            name=name, metric_type=TYPE_HISTOGRAM, tags=tags,
            count=state.count, sum=state.sum, min=state.min,
            max=state.max, mean=mean,
            p50=p50, p95=p95, p99=p99, buckets=buckets,
            digest=digest,
        )

    @staticmethod
    def _quantile(
        buckets: Tuple[HistogramBucket, ...], count: int, q: float
    ) -> Optional[float]:
        """Nearest-rank quantile on cumulative buckets (deterministic)."""
        if count <= 0:
            return None
        rank = math.ceil(q * count)
        for bucket in buckets:
            if bucket.cumulative_count >= rank:
                return bucket.upper_bound
        return buckets[-1].upper_bound if buckets else None

    # -- flush ------------------------------------------------------------

    def flush(self, seq: int) -> FlushReport:
        """Emit per-instrument aggregates and reset collection buffers.

        Counters reset to zero, histogram buckets empty, gauges retained
        (StatsD-faithful). Consumes seq; failed flush consumes it too.
        """
        with self._lock:
            try:
                seq = self._next(seq)
                aggregates: List[Aggregate] = []
                for name in sorted(self._defs):
                    definition = self._defs[name]
                    series_keys = self._series_keys(name, definition.metric_type)
                    for tkey in series_keys:
                        aggregates.append(self.aggregate(name, seq, tkey))
                aggregates.sort(key=lambda a: (a.name, a.tags))
                digest = self._pin(
                    ["flush", seq, [a.digest for a in aggregates]]
                )
                report = FlushReport(
                    flush_seq=seq, aggregates=tuple(aggregates), digest=digest
                )
                for key in list(self._counters):
                    self._counters[key] = 0.0
                    self._counter_samples[key] = 0
                    self._counter_minmax.pop(key, None)
                for key in list(self._histograms):
                    bounds = self._buckets[key[0]]
                    self._histograms[key] = _HistState(
                        bucket_counts=[0] * len(bounds)
                    )
                self._emit(
                    KIND_FLUSHED, seq,
                    instruments=len(aggregates), digest=digest,
                )
                return report
            except MetricsCollectionError as exc:
                self._reject(seq, str(exc))
                raise

    def _series_keys(
        self, name: str, metric_type: str
    ) -> List[Tuple[Tuple[str, str], ...]]:
        store = {
            TYPE_COUNTER: self._counters,
            TYPE_GAUGE: self._gauges,
            TYPE_HISTOGRAM: self._histograms,
        }[metric_type]
        return sorted(k[1] for k in store if k[0] == name)


class _HistState:
    """Mutable per-series histogram accumulation (never leaves the class)."""

    __slots__ = ("count", "sum", "min", "max", "bucket_counts", "values")

    def __init__(self, bucket_counts: Optional[List[int]] = None) -> None:
        self.count = 0
        self.sum = 0.0
        self.min: Optional[float] = None
        self.max: Optional[float] = None
        self.bucket_counts: List[int] = bucket_counts if bucket_counts is not None else []
        self.values: List[float] = []


def main() -> None:
    """Self-check: define, collect, aggregate, flush, verify."""
    mc = MetricsCollection(seed="selfcheck")
    mc.define_counter("req_total", 1, "requests served")
    mc.define_gauge("queue_depth", 2)
    mc.define_histogram("latency_ms", 3, [10, 50, 250, 1000])
    mc.counter("req_total", 7, 4)
    mc.gauge("queue_depth", 12, 5)
    seq = 6
    for value in (5, 20, 60, 300):
        mc.histogram("latency_ms", value, seq)
        seq += 1
    assert mc.aggregate("req_total", 10).sum == 7.0
    assert mc.aggregate("queue_depth", 10).max == 12.0
    agg = mc.aggregate("latency_ms", 10)
    assert agg.count == 4 and agg.p50 == 50.0
    report = mc.flush(11)
    assert len(report.aggregates) == 3
    assert mc.aggregate("req_total", 12).count == 0  # counter reset
    assert mc.aggregate("queue_depth", 12).max == 12.0  # gauge retained
    assert report.verify(mc._seed)
    print("metrics-collection OK: define, collect, aggregate, flush, pins, audit")


if __name__ == "__main__":
    main()
