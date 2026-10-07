"""Model monitoring: drift-detection bookkeeping for ML models.

Research note: production ML systems (MLflow, Evidently, WhyLabs) watch
for *data drift* — the input distribution shifting under a deployed
model — and *performance degradation* — the host-reported metrics
(accuracy, F1, latency) moving off their baseline. The industry-standard
drift score for binned feature histograms is the Population Stability
Index (PSI): ``sum((cand% - ref%) * ln(cand% / ref%))``, floored so zero
bins never divide by zero. PSI < 0.1 means no significant change,
0.1-0.25 a small shift, > 0.25 a significant shift (credit-scoring
convention). This module is the *ledger* layer for that practice:

* **baseline()** pins a reference distribution for a model id (binned
  histograms per feature, pinned by digest; ids never recycled).
* **track()** books one host-reported performance metric observation
  (accuracy, f1, latency ...) at a logical seq.
* **drift()** computes PSI per feature between the pinned baseline and
  a host-supplied candidate distribution and returns the verdict **as
  data** (``drifted`` booleans, never raised).
* **alert()** books an operator alert decision against a pinned reason
  vocabulary (the caller already decided the condition; the ledger just
  books it).

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json`` try/except
fallback, ``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* baselines and host-reported
metric observations; it cannot prove a distribution matches production
traffic, that a tracked metric was measured correctly, or that an
alerted condition was real. A ``drifted=True`` verdict means "the
candidate histogram is far from the baseline by PSI", never "the model
is failing". Raw metric values, distribution counts, and candidate
histograms never cross the audit boundary (digest pins and verdicts
only).
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
MODEL_MONITORING_VERSION = "model-monitoring.v1"

#: Schema pin carried by records and audit events.
MODEL_MONITORING_SCHEMA = "northstar.model-monitoring.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_BASELINE = "model-monitoring.baseline-pinned"
KIND_TRACKED = "model-monitoring.metric-tracked"
KIND_DRIFT = "model-monitoring.drift-checked"
KIND_ALERT = "model-monitoring.alert-raised"
KIND_REJECTED = "model-monitoring.rejected"
_KINDS = frozenset({KIND_BASELINE, KIND_TRACKED, KIND_DRIFT, KIND_ALERT, KIND_REJECTED})

#: Pinned reasons an alert may carry.
REASON_DATA_DRIFT = "data-drift"
REASON_CONCEPT_DRIFT = "concept-drift"
REASON_PERFORMANCE_DROP = "performance-drop"
REASON_SCHEMA_CHANGE = "schema-change"
REASON_MANUAL = "manual"
_REASONS = frozenset(
    {
        REASON_DATA_DRIFT,
        REASON_CONCEPT_DRIFT,
        REASON_PERFORMANCE_DROP,
        REASON_SCHEMA_CHANGE,
        REASON_MANUAL,
    }
)

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256
#: Floor applied to bin proportions so zero bins never divide by zero.
_EPSILON = 1e-4
#: Decimals PSI is rounded to (deterministic digests across platforms).
_PSI_PRECISION = 12
#: Conventional significant-shift threshold (credit-scoring rule of thumb).
DEFAULT_THRESHOLD = 0.25


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class ModelMonitoringError(Exception):
    """Base class for all model-monitoring errors."""


class BadModelError(ModelMonitoringError):
    """model_id is not a usable non-empty str."""


class DuplicateModelError(ModelMonitoringError):
    """model_id already has a pinned baseline; ids are never recycled."""


class UnknownModelError(ModelMonitoringError):
    """model_id names no model this monitor ever saw."""


class BadDistributionError(ModelMonitoringError):
    """Distribution failed validation (features/bins malformed)."""


class DistributionMismatchError(ModelMonitoringError):
    """Candidate distribution does not match the pinned baseline features."""


class BadMetricError(ModelMonitoringError):
    """metric name is not a usable non-empty str."""


class BadValueError(ModelMonitoringError):
    """Metric value is not a finite safe number."""


class BadThresholdError(ModelMonitoringError):
    """Threshold is not a positive finite number."""


class BadReasonError(ModelMonitoringError):
    """Alert reason is outside the pinned vocabulary."""


class BadAlertError(ModelMonitoringError):
    """alert_id is not a usable non-empty str."""


class DuplicateAlertError(ModelMonitoringError):
    """alert_id is already booked; ids are never recycled."""


class SeqOrderError(ModelMonitoringError):
    """seq failed validation or is not strictly greater than the last."""


class AuditKindError(ModelMonitoringError):
    """Unknown audit kind, or a banned key crossed the audit boundary."""


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadModelError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadModelError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadModelError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


def _check_distribution(distribution: Any) -> Dict[str, Tuple[int, ...]]:
    """Validate a binned distribution -> {feature: (counts,)}."""
    if not isinstance(distribution, dict) or not distribution:
        raise BadDistributionError("distribution must be a non-empty mapping")
    clean: Dict[str, Tuple[int, ...]] = {}
    for feature, bins in distribution.items():
        if isinstance(feature, bool) or not isinstance(feature, str) or not feature:
            raise BadDistributionError(f"feature name must be a non-empty str, got {feature!r}")
        if len(feature) > _MAX_ID_LEN:
            raise BadDistributionError(f"feature name too long: {feature!r}")
        if not isinstance(bins, (list, tuple)) or not bins:
            raise BadDistributionError(f"bins for {feature!r} must be a non-empty list")
        counts: List[int] = []
        for b in bins:
            if isinstance(b, bool) or not isinstance(b, int):
                raise BadDistributionError(f"bin counts must be ints, got {type(b).__name__}")
            if b < 0 or abs(b) > _MAX_INT:
                raise BadDistributionError(f"bin count out of range: {b!r}")
            counts.append(b)
        if sum(counts) < 1:
            raise BadDistributionError(f"feature {feature!r} has an empty histogram")
        clean[feature] = tuple(counts)
    return clean


def _check_metric_value(value: Any) -> float:
    if isinstance(value, bool):
        raise BadValueError("metric value must not be a bool")
    if not isinstance(value, (int, float)):
        raise BadValueError(f"metric value must be a number, got {type(value).__name__}")
    f = float(value)
    if f != f or f in (float("inf"), float("-inf")):
        raise BadValueError("metric value must be finite")
    if isinstance(value, int) and abs(value) > _MAX_INT:
        raise BadValueError("metric value outside safe range")
    return f


def _check_threshold(threshold: Any) -> float:
    if isinstance(threshold, bool):
        raise BadThresholdError("threshold must not be a bool")
    if not isinstance(threshold, (int, float)):
        raise BadThresholdError(f"threshold must be a number, got {type(threshold).__name__}")
    t = float(threshold)
    if t != t or t in (float("inf"), float("-inf")) or t <= 0:
        raise BadThresholdError("threshold must be a positive finite number")
    return t


def _check_reason(reason: Any) -> str:
    if isinstance(reason, bool) or not isinstance(reason, str):
        raise BadReasonError(f"reason must be a str, got {type(reason).__name__}")
    if reason not in _REASONS:
        raise BadReasonError(f"reason {reason!r} not in pinned vocabulary")
    return reason


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise ModelMonitoringError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ModelMonitoringError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ModelMonitoringError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


def _dist_canonical(distribution: Dict[str, Tuple[int, ...]]) -> Tuple[Tuple[str, Tuple[int, ...]], ...]:
    return tuple((f, distribution[f]) for f in sorted(distribution))


# ---------------------------------------------------------------------------
# PSI drift math (deterministic, stdlib-only)
# ---------------------------------------------------------------------------


def _psi(ref: Tuple[int, ...], cand: Tuple[int, ...]) -> float:
    """Population Stability Index between two histograms, epsilon-floored."""
    r_total = float(sum(ref))
    c_total = float(sum(cand))
    score = 0.0
    for r, c in zip(ref, cand):
        rp = max(r / r_total, _EPSILON)
        cp = max(c / c_total, _EPSILON)
        score += (cp - rp) * math.log(cp / rp)
    return round(score, _PSI_PRECISION)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineRecord:
    """Pinned reference distribution for one model."""

    model_id: str
    distribution: Tuple[Tuple[str, Tuple[int, ...]], ...]
    digest: str
    seq: int
    schema: str = MODEL_MONITORING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin((self.model_id, list(self.distribution)), "baseline")


@dataclass(frozen=True)
class MetricRecord:
    """One host-reported performance metric observation."""

    metric_id: str
    model_id: str
    metric: str
    value: float
    value_digest: str
    seq: int
    schema: str = MODEL_MONITORING_SCHEMA

    def verify(self) -> bool:
        return self.value_digest == _digest_pin(
            (self.metric_id, self.model_id, self.metric, self.value), "metric"
        )


@dataclass(frozen=True)
class DriftReport:
    """One drift check against the pinned baseline; verdicts are data."""

    drift_id: str
    model_id: str
    threshold: float
    feature_psi: Tuple[Tuple[str, float], ...]
    max_psi: float
    drifted_features: Tuple[str, ...]
    verdict: bool
    digest: str
    seq: int
    schema: str = MODEL_MONITORING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.drift_id,
                self.model_id,
                self.threshold,
                list(self.feature_psi),
                self.max_psi,
                list(self.drifted_features),
                self.verdict,
            ),
            "drift",
        )


@dataclass(frozen=True)
class AlertRecord:
    """One booked alert decision."""

    alert_id: str
    model_id: str
    reason: str
    digest: str
    seq: int
    schema: str = MODEL_MONITORING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.alert_id, self.model_id, self.reason), "alert"
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def model_monitoring_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw metric values and distributions never cross this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "value",
        "values",
        "payload",
        "raw",
        "body",
        "data",
        "message",
        "distribution",
        "candidate",
        "histogram",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "model_monitoring",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------


class ModelMonitoring:
    """Drift-detection bookkeeping ledger: baseline, track, drift, alert."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # model_id -> BaselineRecord
        self._baselines: Dict[str, BaselineRecord] = {}
        # metric_id -> MetricRecord (ordered)
        self._metrics: Dict[str, MetricRecord] = {}
        # drift_id -> DriftReport (ordered)
        self._drifts: Dict[str, DriftReport] = {}
        # alert_id -> AlertRecord
        self._alerts: Dict[str, AlertRecord] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(model_monitoring_audit_event(kind, seq, **detail))

    def _fail(self, seq: int, exc: ModelMonitoringError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def baseline(self, model_id: str, distribution: Dict[str, List[int]], seq: int) -> BaselineRecord:
        """Pin the reference distribution for a model (once; ids never recycled)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                model_id = _check_id(model_id, "model_id")
                clean = _check_distribution(distribution)
            except ModelMonitoringError as exc:
                self._fail(seq, exc, model_id=str(model_id))
            if model_id in self._baselines:
                self._fail(seq, DuplicateModelError(f"baseline already pinned: {model_id!r}"), model_id=model_id)
            canonical = _dist_canonical(clean)
            record = BaselineRecord(
                model_id=model_id,
                distribution=canonical,
                digest=_digest_pin((model_id, list(canonical)), "baseline"),
                seq=seq,
            )
            self._baselines[model_id] = record
            self._emit(
                KIND_BASELINE,
                seq,
                model_id=model_id,
                baseline_digest=record.digest,
                features=sorted(clean),
            )
            return record

    def track(self, model_id: str, metric: str, value: Any, seq: int) -> MetricRecord:
        """Book one host-reported performance metric observation."""
        with self._lock:
            seq = self._claim(seq)
            try:
                model_id = _check_id(model_id, "model_id")
                metric = _check_id(metric, "metric")
                fvalue = _check_metric_value(value)
            except ModelMonitoringError as exc:
                self._fail(seq, exc, model_id=str(model_id))
            if model_id not in self._baselines:
                self._fail(seq, UnknownModelError(f"unknown model: {model_id!r}"), model_id=model_id)
            metric_id = f"track-{len(self._metrics) + 1}"
            record = MetricRecord(
                metric_id=metric_id,
                model_id=model_id,
                metric=metric,
                value=fvalue,
                value_digest=_digest_pin((metric_id, model_id, metric, fvalue), "metric"),
                seq=seq,
            )
            self._metrics[metric_id] = record
            self._emit(
                KIND_TRACKED,
                seq,
                model_id=model_id,
                metric=metric,
                metric_id=metric_id,
                value_digest=record.value_digest,
            )
            return record

    def drift(
        self,
        model_id: str,
        candidate: Dict[str, List[int]],
        seq: int,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> DriftReport:
        """PSI drift check vs the pinned baseline; the verdict is data, never raised."""
        with self._lock:
            seq = self._claim(seq)
            try:
                model_id = _check_id(model_id, "model_id")
                clean = _check_distribution(candidate)
                tvalue = _check_threshold(threshold)
            except ModelMonitoringError as exc:
                self._fail(seq, exc, model_id=str(model_id))
            base = self._baselines.get(model_id)
            if base is None:
                self._fail(seq, UnknownModelError(f"unknown model: {model_id!r}"), model_id=model_id)
            assert base is not None
            base_dist = dict(base.distribution)
            if set(clean) != set(base_dist) or any(
                len(clean[f]) != len(base_dist[f]) for f in clean
            ):
                self._fail(
                    seq,
                    DistributionMismatchError(f"candidate does not match baseline features: {model_id!r}"),
                    model_id=model_id,
                )
            feature_psi: List[Tuple[str, float]] = []
            drifted: List[str] = []
            for feature in sorted(clean):
                score = _psi(base_dist[feature], clean[feature])
                feature_psi.append((feature, score))
                if score >= tvalue:
                    drifted.append(feature)
            max_psi = max((s for _, s in feature_psi), default=0.0)
            drift_id = f"drift-{len(self._drifts) + 1}"
            report = DriftReport(
                drift_id=drift_id,
                model_id=model_id,
                threshold=tvalue,
                feature_psi=tuple(feature_psi),
                max_psi=max_psi,
                drifted_features=tuple(drifted),
                verdict=bool(drifted),
                digest=_digest_pin(
                    (
                        drift_id,
                        model_id,
                        tvalue,
                        [list(p) for p in feature_psi],
                        max_psi,
                        drifted,
                        bool(drifted),
                    ),
                    "drift",
                ),
                seq=seq,
            )
            self._drifts[drift_id] = report
            self._emit(
                KIND_DRIFT,
                seq,
                model_id=model_id,
                drift_id=drift_id,
                threshold=tvalue,
                verdict=report.verdict,
                max_psi=max_psi,
                drifted_features=drifted,
                feature_psi=[[f, s] for f, s in feature_psi],
            )
            return report

    def alert(self, alert_id: str, model_id: str, reason: str, seq: int) -> AlertRecord:
        """Book an alert decision against the pinned reason vocabulary."""
        with self._lock:
            seq = self._claim(seq)
            try:
                if isinstance(alert_id, bool) or not isinstance(alert_id, str) or not alert_id:
                    raise BadAlertError("alert_id must be a non-empty str")
                if len(alert_id) > _MAX_ID_LEN:
                    raise BadAlertError(f"alert_id too long (>{_MAX_ID_LEN} chars)")
                model_id = _check_id(model_id, "model_id")
                reason = _check_reason(reason)
            except ModelMonitoringError as exc:
                self._fail(seq, exc, model_id=str(model_id))
            if model_id not in self._baselines:
                self._fail(seq, UnknownModelError(f"unknown model: {model_id!r}"), model_id=model_id)
            if alert_id in self._alerts:
                self._fail(seq, DuplicateAlertError(f"alert already booked: {alert_id!r}"), alert_id=alert_id)
            record = AlertRecord(
                alert_id=alert_id,
                model_id=model_id,
                reason=reason,
                digest=_digest_pin((alert_id, model_id, reason), "alert"),
                seq=seq,
            )
            self._alerts[alert_id] = record
            self._emit(KIND_ALERT, seq, model_id=model_id, alert_id=alert_id, reason=reason)
            return record

    # -- pure read views ----------------------------------------------------

    def baseline_record(self, model_id: str, seq: int) -> Optional[BaselineRecord]:
        """Pure read: the pinned baseline record, or None."""
        _check_seq(seq)
        with self._lock:
            return self._baselines.get(model_id)

    def metric_history(self, model_id: str, seq: int) -> Tuple[MetricRecord, ...]:
        """Pure read: tracked metric observations for a model, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(m for m in self._metrics.values() if m.model_id == model_id)

    def drift_history(self, model_id: str, seq: int) -> Tuple[DriftReport, ...]:
        """Pure read: drift reports for a model, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(d for d in self._drifts.values() if d.model_id == model_id)

    def alerts_for(self, model_id: str, seq: int) -> Tuple[AlertRecord, ...]:
        """Pure read: alerts booked for a model, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(a for a in self._alerts.values() if a.model_id == model_id)

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: sorted ids of models with a pinned baseline."""
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._baselines))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        _check_seq(seq)
        with self._lock:
            return {
                "models": len(self._baselines),
                "metrics": len(self._metrics),
                "drift_checks": len(self._drifts),
                "alerts": len(self._alerts),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: baseline, track, drift (clean), drift (shifted), alert."""
    monitor = ModelMonitoring()
    base = monitor.baseline("churn-v3", {"age": [100, 200, 300], "tenure": [150, 250]}, 1)
    assert base.verify()
    metric = monitor.track("churn-v3", "accuracy", 0.91, 2)
    assert metric.verify()
    clean = monitor.drift("churn-v3", {"age": [100, 200, 300], "tenure": [150, 250]}, 3)
    assert clean.verify() and not clean.verdict and clean.max_psi == 0.0
    shifted = monitor.drift("churn-v3", {"age": [300, 200, 100], "tenure": [150, 250]}, 4)
    assert shifted.verify() and shifted.verdict and shifted.drifted_features == ("age",)
    alert = monitor.alert("a-1", "churn-v3", REASON_DATA_DRIFT, 5)
    assert alert.verify()
    print("model-monitoring OK: baseline, track, drift, alert, pins, audit")


if __name__ == "__main__":
    main()
