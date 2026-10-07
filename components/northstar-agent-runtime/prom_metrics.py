"""Prometheus metrics: counter/gauge/histogram registry and text exposition (simulated).

Research note: *Prometheus* is the dominant pull-based monitoring system in
cloud-native stacks. Operators declare typed metrics — counters
(monotonically increasing, e.g. requests served), gauges (free values, e.g.
queue depth), histograms (latency distributions as cumulative bucket
counts) — and a Prometheus server *scrapes* them over HTTP in the text
exposition format::

    # HELP http_requests_total Total requests served.
    # TYPE http_requests_total counter
    http_requests_total{method="post"} 1027

This module is the *registry + exposition bookkeeping* of that contract,
not a running exporter: there is no HTTP listener, no scrape target, no
pushgateway, and no sampling of real processes. ``PromMetrics`` records
host-reported metric operations over caller-supplied logical seqs (no
wall-clock) and ``scrape()`` renders the deterministic exposition text that
a real exporter would serve at ``/metrics``.

Load-bearing semantics (the parts that must match Prometheus to be useful):

* **Counters never decrease.** A counter holds the *cumulative* total since
  process start. ``counter_inc()`` with a negative amount raises
  ``CounterDecreaseError`` fail-closed — exactly the way Prometheus client
  libraries refuse negative increments (a decreasing counter breaks
  ``rate()``/``increase()`` queries downstream).
* **Gauges are free.** ``gauge_set()``/``gauge_inc()``/``gauge_dec()``
  accept any finite float; they may go up or down. This is the instrument
  for "current state" (connections open, temperature).
* **Histograms are cumulative.** ``histogram_observe()`` places the value
  in *every* bucket whose upper bound it does not exceed (cumulative
  counts), and increments ``_sum``/``_count``. Buckets must be given in
  strictly increasing order at registration — fail-closed
  ``BucketOrderError`` otherwise.
* **Label sets are identities.** The same metric name with different label
  sets is a different time series. Metric and label names follow the
  Prometheus grammar ``[a-zA-Z_:][a-zA-Z0-9_:]*`` — invalid names raise
  ``InvalidNameError`` fail-closed (a bad name would be rejected at scrape
  time by a real server, so we refuse at registration time).
* **Deterministic exposition.** ``scrape()`` emits ``# HELP``/``# TYPE``
  comments followed by series sorted by (metric name, label-set), so two
  registries with the same logical content produce byte-identical text.
  Every series and every scrape carries a ``sha256:`` digest pin so an
  auditor can verify "this text came from these reported operations".

Fail-closed rules (load-bearing):

* Registering the same metric name twice with a *different* type raises
  ``MetricTypeConflictError`` — a Prometheus target must never serve two
  types under one name.
* Decrementing a counter raises ``CounterDecreaseError``; the pinned value
  never moves backwards.
* Observing into an unregistered histogram, or incrementing an
  unregistered counter, raises ``UnknownMetricError`` — never a silent
  no-op.
* NaN/inf values are refused everywhere (a NaN sample poisons ``rate()``);
  bool is not a number and is refused as a value.
* ``scrape()`` requires monotonically increasing caller seqs so the
  exposition ledger is append-only and auditable.

Honest scope: this books *host-reported* metric operations. It cannot prove
a reported ``http_requests_total`` matches real traffic, cannot observe the
wire, and a lying host gets a consistent, pinned ledger of lies (the GIGO
boundary shared with every bookkeeping module in this batch line). The
histogram math here is exact bucket counting, not an approximation.

Version pin: prom-metrics.v1
Schema pin: northstar.prom-metrics.v1
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
PROM_METRICS_VERSION = "prom-metrics.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.prom-metrics.v1"

#: Prometheus metric/label name grammar.
_NAME_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")

#: Reserved label name (Prometheus exporters must not accept it from users).
_RESERVED_LABEL = "__name__"


class PromMetricsError(Exception):
    """Base error for the Prometheus metrics registry."""


class InvalidNameError(PromMetricsError):
    """Metric or label name violates the Prometheus grammar."""


class MetricTypeConflictError(PromMetricsError):
    """Same metric name registered under two different types."""


class UnknownMetricError(PromMetricsError):
    """Operation on a metric name that was never registered."""


class CounterDecreaseError(PromMetricsError):
    """A counter was asked to move backwards. Counters never decrease."""


class BucketOrderError(PromMetricsError):
    """Histogram bucket bounds are not strictly increasing."""


class LabelMismatchError(PromMetricsError):
    """Label set does not match the metric's registered label names."""


class AuditError(PromMetricsError):
    """Bad audit event kind or arguments."""


def _check_seq(seq: Any) -> int:
    """Validate a caller-supplied logical sequence number."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise PromMetricsError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise PromMetricsError("seq must be >= 0")
    return seq


def _check_name(name: Any, what: str) -> str:
    """Validate a metric or label name against the Prometheus grammar."""
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise InvalidNameError(f"invalid {what} name: {name!r}")
    return name


def _check_labels(labels: Any, expected: Tuple[str, ...]) -> Tuple[Tuple[str, str], ...]:
    """Validate a label mapping: names grammar, str values, exact name set."""
    if not isinstance(labels, Mapping):
        raise PromMetricsError(f"labels must be a mapping, got {type(labels).__name__}")
    if tuple(sorted(labels.keys())) != tuple(sorted(expected)):
        raise LabelMismatchError(
            f"label names {tuple(sorted(labels.keys()))} != registered {tuple(sorted(expected))}"
        )
    out = []
    for key in sorted(labels.keys()):
        _check_name(key, "label")
        value = labels[key]
        if not isinstance(value, str):
            raise PromMetricsError(f"label value must be str, got {type(value).__name__}")
        out.append((key, value))
    return tuple(out)


def _check_value(value: Any, what: str) -> float:
    """Validate a numeric sample: finite float, never bool/NaN/inf."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PromMetricsError(f"{what} must be a number, got {type(value).__name__}")
    fvalue = float(value)
    if not math.isfinite(fvalue):
        raise PromMetricsError(f"{what} must be finite, got {fvalue!r}")
    if isinstance(value, int) and abs(value) > 2**53:
        raise PromMetricsError(f"{what} int exceeds 2**53 precision bound")
    return fvalue


def _digest(obj: Any) -> str:
    """Return a ``sha256:`` pin over the canonical encoding of obj."""
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


def _escape_label_value(value: str) -> str:
    """Escape a label value for the exposition format."""
    return value.replace("\\", r"\\").replace('"', r'\"').replace("\n", r"\n")


@dataclass(frozen=True)
class SeriesIdentity:
    """Frozen identity of one time series: metric name + sorted label set."""

    metric: str
    labels: Tuple[Tuple[str, str], ...]
    digest: str
    version: str = PROM_METRICS_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "metric": self.metric,
            "labels": [list(pair) for pair in self.labels],
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CounterSample:
    """Frozen record of a counter increment."""

    metric: str
    labels: Tuple[Tuple[str, str], ...]
    delta: float
    new_value: float
    seq: int
    digest: str
    version: str = PROM_METRICS_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "metric": self.metric,
            "labels": [list(pair) for pair in self.labels],
            "delta": self.delta,
            "new_value": self.new_value,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class GaugeSample:
    """Frozen record of a gauge mutation."""

    metric: str
    labels: Tuple[Tuple[str, str], ...]
    op: str  # "set" | "inc" | "dec"
    value: float
    seq: int
    digest: str
    version: str = PROM_METRICS_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "metric": self.metric,
            "labels": [list(pair) for pair in self.labels],
            "op": self.op,
            "value": self.value,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class HistogramObservation:
    """Frozen record of one histogram observation."""

    metric: str
    labels: Tuple[Tuple[str, str], ...]
    value: float
    bucket_counts: Tuple[int, ...]
    count: int
    total: float
    seq: int
    digest: str
    version: str = PROM_METRICS_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "metric": self.metric,
            "labels": [list(pair) for pair in self.labels],
            "value": self.value,
            "bucket_counts": list(self.bucket_counts),
            "count": self.count,
            "total": self.total,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ScrapeReport:
    """Frozen record of one exposition scrape."""

    seq: int
    series_count: int
    text_digest: str
    text: str
    digest: str
    version: str = PROM_METRICS_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "seq": self.seq,
            "series_count": self.series_count,
            "text_digest": self.text_digest,
            "digest": self.digest,
        }


@dataclass
class _MetricDef:
    """Mutable per-metric bookkeeping (internal; frozen records are the API)."""

    name: str
    mtype: str  # "counter" | "gauge" | "histogram"
    help_text: str
    label_names: Tuple[str, ...]
    buckets: Optional[Tuple[float, ...]] = None
    # Per-series state keyed by sorted label tuple.
    series: Dict[Tuple[Tuple[str, str], ...], Any] = field(default_factory=dict)


class PromMetrics:
    """Prometheus-style metric registry and exposition renderer.

    House style: caller-supplied int seqs (no wall-clock), fail-closed,
    stdlib-only, RLock-guarded, frozen records with ``sha256:`` digest pins.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._metrics: Dict[str, _MetricDef] = {}
        self._last_scrape_seq = -1

    # -- registration -----------------------------------------------------

    def register(
        self,
        name: str,
        mtype: str,
        seq: int,
        label_names: Tuple[str, ...] = (),
        help_text: str = "",
        buckets: Optional[Tuple[float, ...]] = None,
    ) -> SeriesIdentity:
        """Register a metric. Same name + different type is refused."""
        seq = _check_seq(seq)
        _check_name(name, "metric")
        if mtype not in ("counter", "gauge", "histogram"):
            raise PromMetricsError(f"unknown metric type: {mtype!r}")
        if not isinstance(help_text, str):
            raise PromMetricsError("help_text must be str")
        names = tuple(label_names)
        for label in names:
            _check_name(label, "label")
            if label == _RESERVED_LABEL:
                raise InvalidNameError(f"reserved label name: {label!r}")
            if mtype == "histogram" and label == "le":
                raise InvalidNameError(
                    "'le' is a reserved histogram label and cannot be registered"
                )
        if len(set(names)) != len(names):
            raise PromMetricsError("duplicate label names")
        bucket_tuple: Optional[Tuple[float, ...]] = None
        if mtype == "histogram":
            if not buckets:
                raise PromMetricsError("histogram requires non-empty buckets")
            bucket_tuple = tuple(_check_value(b, "bucket bound") for b in buckets)
            if len(set(bucket_tuple)) != len(bucket_tuple):
                raise BucketOrderError("duplicate bucket bounds")
            for lo, hi in zip(bucket_tuple, bucket_tuple[1:]):
                if not lo < hi:
                    raise BucketOrderError("bucket bounds must be strictly increasing")
        elif buckets is not None:
            raise PromMetricsError("buckets are only valid for histogram")
        with self._lock:
            existing = self._metrics.get(name)
            if existing is not None:
                if existing.mtype != mtype:
                    raise MetricTypeConflictError(
                        f"{name!r} already registered as {existing.mtype}"
                    )
                if tuple(sorted(existing.label_names)) != tuple(sorted(names)):
                    raise LabelMismatchError(f"{name!r} label names differ from registration")
                raise PromMetricsError(f"{name!r} is already registered")
            self._metrics[name] = _MetricDef(
                name=name,
                mtype=mtype,
                help_text=help_text,
                label_names=tuple(sorted(names)),
                buckets=bucket_tuple,
            )
            digest = _digest(
                {
                    "version": PROM_METRICS_VERSION,
                    "name": name,
                    "type": mtype,
                    "labels": sorted(names),
                    "buckets": list(bucket_tuple) if bucket_tuple else None,
                }
            )
            return SeriesIdentity(metric=name, labels=(), digest=digest)

    # -- counters ---------------------------------------------------------

    def counter_inc(
        self, name: str, labels: Mapping[str, str], amount: float, seq: int
    ) -> CounterSample:
        """Increment a counter. Negative amounts are refused fail-closed."""
        seq = _check_seq(seq)
        amount = _check_value(amount, "counter amount")
        if amount < 0:
            raise CounterDecreaseError("counters never decrease")
        with self._lock:
            metric = self._require(name, "counter")
            key = _check_labels(labels, metric.label_names)
            old = metric.series.get(key, 0.0)
            new = old + amount
            metric.series[key] = new
            digest = _digest(
                {
                    "version": PROM_METRICS_VERSION,
                    "op": "counter_inc",
                    "metric": name,
                    "labels": list(key),
                    "delta": amount,
                    "new": new,
                    "seq": seq,
                }
            )
            return CounterSample(
                metric=name, labels=key, delta=amount, new_value=new, seq=seq, digest=digest
            )

    # -- gauges -----------------------------------------------------------

    def gauge_set(
        self, name: str, labels: Mapping[str, str], value: float, seq: int
    ) -> GaugeSample:
        """Set a gauge to an absolute value."""
        return self._gauge_op(name, labels, value, "set", seq)

    def gauge_inc(
        self, name: str, labels: Mapping[str, str], amount: float, seq: int
    ) -> GaugeSample:
        """Add to a gauge (amount may be negative)."""
        seq = _check_seq(seq)
        amount = _check_value(amount, "gauge amount")
        with self._lock:
            metric = self._require(name, "gauge")
            key = _check_labels(labels, metric.label_names)
            old = metric.series.get(key, 0.0)
            return self._gauge_apply(metric, key, "inc", old + amount, seq)

    def gauge_dec(
        self, name: str, labels: Mapping[str, str], amount: float, seq: int
    ) -> GaugeSample:
        """Subtract from a gauge (amount may be negative)."""
        seq = _check_seq(seq)
        amount = _check_value(amount, "gauge amount")
        with self._lock:
            metric = self._require(name, "gauge")
            key = _check_labels(labels, metric.label_names)
            old = metric.series.get(key, 0.0)
            return self._gauge_apply(metric, key, "dec", old - amount, seq)

    def _gauge_op(
        self, name: str, labels: Mapping[str, str], value: float, op: str, seq: int
    ) -> GaugeSample:
        seq = _check_seq(seq)
        value = _check_value(value, "gauge value")
        with self._lock:
            metric = self._require(name, "gauge")
            key = _check_labels(labels, metric.label_names)
            return self._gauge_apply(metric, key, op, value, seq)

    def _gauge_apply(
        self, metric: _MetricDef, key: Tuple[Tuple[str, str], ...], op: str, value: float, seq: int
    ) -> GaugeSample:
        metric.series[key] = value
        digest = _digest(
            {
                "version": PROM_METRICS_VERSION,
                "op": f"gauge_{op}",
                "metric": metric.name,
                "labels": list(key),
                "value": value,
                "seq": seq,
            }
        )
        return GaugeSample(
            metric=metric.name, labels=key, op=op, value=value, seq=seq, digest=digest
        )

    # -- histograms -------------------------------------------------------

    def histogram_observe(
        self, name: str, labels: Mapping[str, str], value: float, seq: int
    ) -> HistogramObservation:
        """Observe a value: cumulative bucket counts + sum/count."""
        seq = _check_seq(seq)
        value = _check_value(value, "observed value")
        with self._lock:
            metric = self._require(name, "histogram")
            key = _check_labels(labels, metric.label_names)
            assert metric.buckets is not None
            state = metric.series.get(key)
            if state is None:
                state = {"counts": [0] * len(metric.buckets), "count": 0, "total": 0.0}
                metric.series[key] = state
            counts = state["counts"]
            for i, bound in enumerate(metric.buckets):
                if value <= bound:
                    counts[i] += 1
            state["count"] += 1
            state["total"] += value
            digest = _digest(
                {
                    "version": PROM_METRICS_VERSION,
                    "op": "histogram_observe",
                    "metric": name,
                    "labels": list(key),
                    "value": value,
                    "counts": list(counts),
                    "count": state["count"],
                    "total": state["total"],
                    "seq": seq,
                }
            )
            return HistogramObservation(
                metric=name,
                labels=key,
                value=value,
                bucket_counts=tuple(counts),
                count=state["count"],
                total=state["total"],
                seq=seq,
                digest=digest,
            )

    # -- views ------------------------------------------------------------

    def sample(self, name: str, labels: Mapping[str, str]) -> Any:
        """Return the current value/state of one series (None if absent)."""
        with self._lock:
            metric = self._require(name)
            key = _check_labels(labels, metric.label_names)
            state = metric.series.get(key)
            if state is None:
                return None
            if metric.mtype == "histogram":
                return {
                    "buckets": list(state["counts"]),
                    "count": state["count"],
                    "total": state["total"],
                }
            return state

    def metrics(self) -> Tuple[str, ...]:
        """Sorted registered metric names."""
        with self._lock:
            return tuple(sorted(self._metrics))

    # -- exposition -------------------------------------------------------

    def scrape(self, seq: int) -> ScrapeReport:
        """Render the deterministic Prometheus text exposition format."""
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_scrape_seq:
                raise PromMetricsError("scrape seqs must strictly increase")
            self._last_scrape_seq = seq
            lines: List[str] = []
            series_count = 0
            for name in sorted(self._metrics):
                metric = self._metrics[name]
                lines.append(f"# HELP {name} {metric.help_text}")
                lines.append(f"# TYPE {name} {metric.mtype}")
                keys = sorted(metric.series.keys())
                if metric.mtype == "histogram":
                    assert metric.buckets is not None
                    for key in keys:
                        state = metric.series[key]
                        base_pairs = list(key)
                        for bound, count in zip(metric.buckets, state["counts"]):
                            # state["counts"] is already cumulative at observe time.
                            label_str = self._label_string(
                                tuple(base_pairs + [("le", self._fmt_float(bound))])
                            )
                            lines.append(f"{name}_bucket{label_str} {count}")
                        label_str = self._label_string(tuple(base_pairs + [("le", "+Inf")]))
                        lines.append(f"{name}_bucket{label_str} {state['count']}")
                        sum_str = self._label_string(key)
                        lines.append(f"{name}_sum{sum_str} {self._fmt_float(state['total'])}")
                        lines.append(f"{name}_count{sum_str} {state['count']}")
                        series_count += len(metric.buckets) + 3
                else:
                    for key in keys:
                        label_str = self._label_string(key)
                        lines.append(
                            f"{name}{label_str} {self._fmt_float(metric.series[key])}"
                        )
                        series_count += 1
            text = "\n".join(lines) + ("\n" if lines else "")
            text_digest = _digest({"version": PROM_METRICS_VERSION, "text": text})
            digest = _digest(
                {
                    "version": PROM_METRICS_VERSION,
                    "op": "scrape",
                    "seq": seq,
                    "series_count": series_count,
                    "text_digest": text_digest,
                }
            )
            return ScrapeReport(
                seq=seq,
                series_count=series_count,
                text_digest=text_digest,
                text=text,
                digest=digest,
            )

    # -- internals --------------------------------------------------------

    def _require(self, name: str, mtype: Optional[str] = None) -> _MetricDef:
        _check_name(name, "metric")
        metric = self._metrics.get(name)
        if metric is None:
            raise UnknownMetricError(f"unknown metric: {name!r}")
        if mtype is not None and metric.mtype != mtype:
            raise MetricTypeConflictError(f"{name!r} is a {metric.mtype}, not a {mtype}")
        return metric

    @staticmethod
    def _label_string(key: Tuple[Tuple[str, str], ...]) -> str:
        if not key:
            return ""
        pairs = sorted(key, key=lambda pair: pair[0])
        return "{" + ",".join(
            f'{name}="{_escape_label_value(value)}"' for name, value in pairs
        ) + "}"

    @staticmethod
    def _fmt_float(value: float) -> str:
        if value == int(value) and abs(value) < 1e16:
            return str(int(value))
        text = repr(value)
        if text in ("inf", "-inf", "nan"):
            raise PromMetricsError(f"cannot render non-finite value {text!r}")
        return text


def prom_metrics_audit_event(kind: str, seq: int, detail: dict) -> dict:
    """Shape an ``audit.ndjson/1`` record for Prometheus-metrics events."""
    seq = _check_seq(seq)
    allowed = {"registered", "counter-inc", "gauge-op", "observed", "scraped", "rejected"}
    if kind not in allowed:
        raise AuditError(f"unknown audit kind: {kind!r}")
    if not isinstance(detail, dict):
        raise AuditError("detail must be a dict")
    return {
        "schema": SCHEMA_PIN,
        "version": PROM_METRICS_VERSION,
        "audit_seq": seq,
        "event": "prom-metrics",
        "kind": kind,
        "detail": detail,
    }


def main() -> None:
    """Self-check: register, mutate, scrape, verify exposition."""
    pm = PromMetrics()
    pm.register("http_requests_total", "counter", 0, label_names=("method",), help_text="requests")
    pm.register("queue_depth", "gauge", 1, help_text="depth")
    pm.register("latency_seconds", "histogram", 2, buckets=(0.1, 0.5, 1.0), help_text="lat")
    pm.counter_inc("http_requests_total", {"method": "post"}, 5, 3)
    pm.gauge_set("queue_depth", {}, 7, 4)
    pm.histogram_observe("latency_seconds", {}, 0.2, 5)
    report = pm.scrape(6)
    assert "http_requests_total{method=\"post\"} 5" in report.text
    assert 'latency_seconds_bucket{le="0.1"} 0' in report.text
    assert 'latency_seconds_bucket{le="0.5"} 1' in report.text
    assert 'latency_seconds_bucket{le="+Inf"} 1' in report.text
    assert "latency_seconds_sum 0.2" in report.text
    assert "latency_seconds_count 1" in report.text
    assert report.series_count == 8
    print("prom-metrics OK: register, counter, gauge, histogram, scrape")


if __name__ == "__main__":
    main()
