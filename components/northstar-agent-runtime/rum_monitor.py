"""Real User Monitoring (RUM) web-vitals bookkeeping (thirty-second batch).

Google Web Vitals-shaped measurement as a deterministic single-host
ledger:

* :meth:`RUMMonitor.session` registers a page session (``ses-N`` ids).
* :meth:`RUMMonitor.end_session` closes a session (terminal).
* :meth:`RUMMonitor.vital` records one web-vital sample (``vtl-N`` ids)
  for a live session. The metric's rating (``good`` /
  ``needs-improvement`` / ``poor``) is computed from pinned threshold
  tables and stored as data.
* :meth:`RUMMonitor.alert` defines a poor-fraction alert rule
  (``alr-N`` ids); :meth:`RUMMonitor.evaluate` books one evaluation
  (``evl-N`` ids) reporting per-rule ``triggered`` verdicts as data.
* :meth:`RUMMonitor.summary` books a per-metric rollup (``sum-N`` ids)
  with rating counts, poor fraction, and the exact median.

The metric vocabulary and thresholds mirror the Web Vitals initiative
(https://web.dev/articles/vitals):

* ``lcp`` — Largest Contentful Paint (ms):      good <= 2500, ni <= 4000
* ``inp`` — Interaction to Next Paint (ms):    good <= 200,  ni <= 500
* ``cls`` — Cumulative Layout Shift (unitless): good <= 0.1,  ni <= 0.25
* ``fcp`` — First Contentful Paint (ms):        good <= 1800, ni <= 3000
* ``ttfb`` — Time to First Byte (ms):           good <= 800,  ni <= 1800

House rules: no wall-clock (callers inject integer seqs), frozen
dataclasses, fail-closed validation (structural problems raise;
*queries* over empty data report zeros/``False`` as data, never
exceptions), stdlib-only, records sealed with ``sha256:`` digest pins
over the canonical payload and chained per ledger via ``prev_digest``
(``"genesis"`` for the first). Every mutation consumes its seq —
failed mutations advance the ledger position too, so the audit trail
stays totally ordered. RLock-guarded for concurrent callers.
State transitions emit ``audit.ndjson/1`` events.

Values are rounded to 6 decimal places on ingest (canonical form), so
pins recompute identically across hosts; ratings derive from the
rounded value. Attributes and URLs are host-reported: URL query
strings may carry PII, so ``url`` values never cross the audit
boundary (ids + digests + ratings only).

Honest boundary: this module books *host-reported* measurements
consistently (digests recompute, the chain is append-only, ratings and
fractions are exact over the ledger). It cannot prove a measurement
came from a real browser, that samples are unbiased, or that
under-reporting did not happen — the GIGO boundary sits at
:meth:`session` and :meth:`vital`. Alerting is a deterministic
threshold report, not a statistical significance test.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from threading import RLock
from typing import Any, Mapping

#: Version pin for this module's record shape.
RUM_MONITOR_VERSION = "rum-monitor.v1"

#: Schema pin carried by records and audit events.
RUM_MONITOR_SCHEMA = "northstar.rum-monitor.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Genesis marker for the first record in a hash chain.
_GENESIS = "genesis"

#: Audit event kinds.
KIND_SESSION_STARTED = "rum.session-started"
KIND_SESSION_ENDED = "rum.session-ended"
KIND_VITAL_RECORDED = "rum.vital-recorded"
KIND_ALERT_DEFINED = "rum.alert-defined"
KIND_ALERT_EVALUATED = "rum.alert-evaluated"
KIND_SUMMARY_REPORTED = "rum.summary-reported"
KIND_REJECTED = "rum.rejected"
_KINDS = (
    KIND_SESSION_STARTED,
    KIND_SESSION_ENDED,
    KIND_VITAL_RECORDED,
    KIND_ALERT_DEFINED,
    KIND_ALERT_EVALUATED,
    KIND_SUMMARY_REPORTED,
    KIND_REJECTED,
)

#: Pinned web-vital metric vocabulary.
METRIC_LCP = "lcp"
METRIC_INP = "inp"
METRIC_CLS = "cls"
METRIC_FCP = "fcp"
METRIC_TTFB = "ttfb"
METRICS = (METRIC_LCP, METRIC_INP, METRIC_CLS, METRIC_FCP, METRIC_TTFB)

#: Pinned rating vocabulary.
RATING_GOOD = "good"
RATING_NEEDS_IMPROVEMENT = "needs-improvement"
RATING_POOR = "poor"
RATINGS = (RATING_GOOD, RATING_NEEDS_IMPROVEMENT, RATING_POOR)

#: Pinned (good_upper, needs_improvement_upper) thresholds per metric.
#: Values are compared with ``<=``; anything above the ni upper is poor.
_THRESHOLDS = {
    METRIC_LCP: (2500.0, 4000.0),
    METRIC_INP: (200.0, 500.0),
    METRIC_CLS: (0.1, 0.25),
    METRIC_FCP: (1800.0, 3000.0),
    METRIC_TTFB: (800.0, 1800.0),
}
#: Digest pin of the threshold table so threshold drift is detectable.
_THRESHOLD_DIGEST = "sha256:" + hashlib.sha256(
    json.dumps(
        {k: _THRESHOLDS[k] for k in sorted(_THRESHOLDS)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()

#: Pinned alert severity vocabulary.
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"
SEVERITIES = (SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL)

#: Session states.
STATE_ACTIVE = "active"
STATE_ENDED = "ended"

#: Validation caps.
MAX_ID_LEN = 128
MAX_PAGE_LEN = 512
MAX_URL_LEN = 2048
MAX_ATTRIBUTES = 32
MAX_ATTR_KEY_LEN = 64
MAX_ATTR_VALUE_LEN = 1024
MAX_TIME_VALUE_MS = 3_600_000.0  # 1 hour — sane upper bound for ms metrics
MAX_CLS_VALUE = 10.0
MAX_WINDOW = 10_000
_MIN_SAFE_FLOAT = -1e18

#: Safe integer range for attribute values (JCS >2^53 discipline).
_SAFE_INT = 2 ** 53


class RUMError(ValueError):
    """A malformed request or a refused state transition."""


class SeqOrderError(RUMError):
    """A mutation seq that is not strictly greater than the last one."""


class UnknownSessionError(RUMError):
    """Lookup of a session id the ledger does not hold."""


class DuplicateSessionError(RUMError):
    """Session id already registered (ids are never recycled)."""


class SessionStateError(RUMError):
    """Operation refused because the session is not active."""


class UnknownMetricError(RUMError):
    """Metric name outside the pinned web-vitals vocabulary."""


class BadValueError(RUMError):
    """A vital value that is not a finite, in-range number."""


class DuplicateAlertError(RUMError):
    """Alert id already defined (ids are never recycled)."""


class UnknownAlertError(RUMError):
    """Lookup of an alert id the ledger does not hold."""


class BadAlertError(RUMError):
    """A malformed alert rule definition."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RUMError(f"{field_name} must be a non-negative int")
    return value


def _check_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise RUMError(f"{field_name} must be a non-empty string")
    if len(value) > MAX_ID_LEN:
        raise RUMError(f"{field_name} must be at most {MAX_ID_LEN} chars")
    return value


def _check_metric(value: Any) -> str:
    if value not in _THRESHOLDS:
        raise UnknownMetricError(
            f"unknown metric {value!r}; expected one of {sorted(_THRESHOLDS)}"
        )
    return value


def _check_value(metric: str, value: Any) -> float:
    """Validate and canonicalize (6dp) a vital measurement."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadValueError("vital value must be a real number")
    if not math.isfinite(value) or value < 0:
        raise BadValueError("vital value must be finite and non-negative")
    cap = MAX_CLS_VALUE if metric == METRIC_CLS else MAX_TIME_VALUE_MS
    if value > cap:
        raise BadValueError(f"vital value for {metric} exceeds cap {cap}")
    return round(float(value), 6)


def _check_severity(value: Any) -> str:
    if value not in SEVERITIES:
        raise BadAlertError(
            f"severity must be one of {sorted(SEVERITIES)}, got {value!r}"
        )
    return value


def _check_threshold(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadAlertError("poor_fraction_threshold must be a real number")
    if not math.isfinite(value) or not (0.0 < value <= 1.0):
        raise BadAlertError("poor_fraction_threshold must be in (0, 1]")
    return float(value)


def _check_window(value: Any) -> int:
    _check_seq(value, "window")
    if not 1 <= value <= MAX_WINDOW:
        raise BadAlertError(f"window must be within 1..{MAX_WINDOW}")
    return value


def _check_attributes(value: Any) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise RUMError("attributes must be a mapping")
    if len(value) > MAX_ATTRIBUTES:
        raise RUMError(f"attributes must hold at most {MAX_ATTRIBUTES} entries")
    out: dict[str, Any] = {}
    for key, val in value.items():
        if not isinstance(key, str) or not key or len(key) > MAX_ATTR_KEY_LEN:
            raise RUMError("attribute keys must be non-empty strings")
        if isinstance(val, bool):
            out[key] = val
        elif isinstance(val, int):
            if abs(val) >= _SAFE_INT:
                raise RUMError("attribute int outside safe range")
            out[key] = val
        elif isinstance(val, str):
            if len(val) > MAX_ATTR_VALUE_LEN:
                raise RUMError("attribute string value too long")
            out[key] = val
        elif val is None:
            out[key] = None
        else:
            raise RUMError("attribute values must be str/int/bool/None")
    return out


def _check_url(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RUMError("url must be a string")
    if len(value) > MAX_URL_LEN:
        raise RUMError(f"url must be at most {MAX_URL_LEN} chars")
    return value


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    # Payloads hold str/int/bool/None, lists, and floats rounded to 6dp on
    # ingest — deterministic round-trip serialization per float bit pattern.
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def _rate(metric: str, value: float) -> str:
    """Compute the rating of a canonicalized value against pinned thresholds."""
    good_upper, ni_upper = _THRESHOLDS[metric]
    if value <= good_upper:
        return RATING_GOOD
    if value <= ni_upper:
        return RATING_NEEDS_IMPROVEMENT
    return RATING_POOR


def _session_payload(
    record_id: str, session_id: str, page: str, attributes: Mapping[str, Any],
    seq: int, prev_digest: str,
) -> Mapping[str, Any]:
    return {
        "record_id": record_id,
        "session_id": session_id,
        "page": page,
        "attributes": dict(attributes),
        "state": STATE_ACTIVE,
        "seq": seq,
        "prev_digest": prev_digest,
        "schema": RUM_MONITOR_SCHEMA,
        "module_version": RUM_MONITOR_VERSION,
    }


@dataclass(frozen=True)
class SessionRecord:
    """One registered page session (state ``active`` until ended)."""

    record_id: str
    session_id: str
    page: str
    attributes: Mapping[str, Any]
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True when the record is intact."""
        return self.digest == _pin(
            _session_payload(
                self.record_id, self.session_id, self.page,
                self.attributes, self.seq, self.prev_digest,
            )
        )


def _end_payload(record_id: str, session_id: str, seq: int,
                 prev_digest: str) -> Mapping[str, Any]:
    return {
        "record_id": record_id,
        "session_id": session_id,
        "state": STATE_ENDED,
        "seq": seq,
        "prev_digest": prev_digest,
        "schema": RUM_MONITOR_SCHEMA,
        "module_version": RUM_MONITOR_VERSION,
    }


@dataclass(frozen=True)
class SessionEndRecord:
    """Terminal closure of a session."""

    record_id: str
    session_id: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            _end_payload(self.record_id, self.session_id, self.seq,
                        self.prev_digest)
        )


def _sample_payload(
    record_id: str, session_id: str, metric: str, value: float, rating: str,
    url: str, seq: int, prev_digest: str,
) -> Mapping[str, Any]:
    return {
        "record_id": record_id,
        "session_id": session_id,
        "metric": metric,
        "value": value,
        "rating": rating,
        "url": url,
        "seq": seq,
        "prev_digest": prev_digest,
        "schema": RUM_MONITOR_SCHEMA,
        "module_version": RUM_MONITOR_VERSION,
    }


@dataclass(frozen=True)
class VitalSample:
    """One immutable web-vital measurement with a computed rating."""

    record_id: str
    session_id: str
    metric: str
    value: float
    rating: str
    url: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True when the sample is intact."""
        return self.digest == _pin(
            _sample_payload(
                self.record_id, self.session_id, self.metric, self.value,
                self.rating, self.url, self.seq, self.prev_digest,
            )
        )


def _alert_payload(
    record_id: str, alert_id: str, metric: str, threshold: float,
    window: int, severity: str, seq: int, prev_digest: str,
) -> Mapping[str, Any]:
    return {
        "record_id": record_id,
        "alert_id": alert_id,
        "metric": metric,
        "poor_fraction_threshold": threshold,
        "window": window,
        "severity": severity,
        "seq": seq,
        "prev_digest": prev_digest,
        "schema": RUM_MONITOR_SCHEMA,
        "module_version": RUM_MONITOR_VERSION,
    }


@dataclass(frozen=True)
class AlertRule:
    """A poor-fraction alert rule over the trailing window of samples."""

    record_id: str
    alert_id: str
    metric: str
    poor_fraction_threshold: float
    window: int
    severity: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            _alert_payload(
                self.record_id, self.alert_id, self.metric,
                self.poor_fraction_threshold, self.window, self.severity,
                self.seq, self.prev_digest,
            )
        )


@dataclass(frozen=True)
class RuleVerdict:
    """Per-rule outcome inside an :class:`AlertEvaluation`."""

    alert_id: str
    metric: str
    triggered: bool
    poor_fraction: float
    window_samples: int
    threshold: float


def _eval_payload(
    record_id: str, verdicts: tuple, seq: int, prev_digest: str,
) -> Mapping[str, Any]:
    return {
        "record_id": record_id,
        "verdicts": [
            {
                "alert_id": v.alert_id,
                "metric": v.metric,
                "triggered": v.triggered,
                "poor_fraction": v.poor_fraction,
                "window_samples": v.window_samples,
                "threshold": v.threshold,
            }
            for v in verdicts
        ],
        "seq": seq,
        "prev_digest": prev_digest,
        "schema": RUM_MONITOR_SCHEMA,
        "module_version": RUM_MONITOR_VERSION,
    }


@dataclass(frozen=True)
class AlertEvaluation:
    """One booked evaluation of all alert rules (verdicts are data)."""

    record_id: str
    verdicts: tuple
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            _eval_payload(self.record_id, self.verdicts, self.seq,
                         self.prev_digest)
        )


def _summary_payload(
    record_id: str, metric: str, counts: Mapping[str, int], total: int,
    poor_fraction: float, median: float | None, seq: int, prev_digest: str,
) -> Mapping[str, Any]:
    return {
        "record_id": record_id,
        "metric": metric,
        "counts": dict(counts),
        "total": total,
        "poor_fraction": poor_fraction,
        "median": median,
        "seq": seq,
        "prev_digest": prev_digest,
        "schema": RUM_MONITOR_SCHEMA,
        "module_version": RUM_MONITOR_VERSION,
    }


@dataclass(frozen=True)
class MetricSummary:
    """Per-metric rollup: rating counts, poor fraction, exact median."""

    record_id: str
    metric: str
    counts: Mapping[str, int]
    total: int
    poor_fraction: float
    median: float | None
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            _summary_payload(
                self.record_id, self.metric, self.counts, self.total,
                self.poor_fraction, self.median, self.seq, self.prev_digest,
            )
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def rum_monitor_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the RUM monitor.

    Carries ids, digests, ratings, and aggregate counts only — never
    ``url`` values or attribute values.
    """
    if kind not in _KINDS:
        raise RUMError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = ("url", "attributes", "page")
    for key in banned:
        if key in detail:
            raise RUMError(f"audit detail must not carry {key!r}")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "rum_monitor",
        "module_version": RUM_MONITOR_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# RUMMonitor
# ---------------------------------------------------------------------------


class RUMMonitor:
    """Append-only ledger of page sessions and web-vital samples.

    All mutations require a strictly increasing caller-supplied ``seq``
    (logical time — no wall-clock reads anywhere). Failed mutations
    still consume their seq, keeping the audit trail totally ordered.
    RLock-guarded for concurrent callers.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._sessions: dict[str, SessionRecord] = {}
        self._session_state: dict[str, str] = {}
        self._samples: list[VitalSample] = []
        self._by_metric: dict[str, list[VitalSample]] = {}
        self._alerts: dict[str, AlertRule] = {}
        self._last_seq = -1
        self._next_n = 1
        self._audit: list[Mapping[str, Any]] = []

    # -- internals --------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (last={self._last_seq}, saw={seq})"
            )
        # Consumed up front: failed mutations advance the position too.
        self._last_seq = seq
        return seq

    def _next_id(self, prefix: str) -> str:
        record_id = f"{prefix}-{self._next_n}"
        self._next_n += 1
        return record_id

    def _prev(self, ledger: Any) -> str:
        return ledger[-1].digest if ledger else _GENESIS

    def _audit_event(self, kind: str, seq: int,
                     **detail: Any) -> Mapping[str, Any]:
        event = rum_monitor_audit_event(kind, seq, **detail)
        self._audit.append(event)
        return event

    def _reject(self, seq: int, reason: str, error: type = RUMError,
               **detail: Any) -> RUMError:
        self._audit_event(KIND_REJECTED, seq, reason=reason, **detail)
        return error(reason)

    # -- sessions ---------------------------------------------------------

    def session(
        self,
        session_id: str,
        seq: int,
        page: str = "",
        attributes: Mapping[str, Any] | None = None,
    ) -> SessionRecord:
        """Register a page session (state ``active``).

        Fails closed on duplicate ids — ids are never recycled.
        """
        with self._lock:
            self._claim_seq(seq)
            _check_id(session_id, "session_id")
            if not isinstance(page, str) or len(page) > MAX_PAGE_LEN:
                raise self._reject(seq, "page must be a string", target="page")
            attrs = _check_attributes(attributes)
            if session_id in self._sessions:
                raise self._reject(
                    seq, f"duplicate session id {session_id!r}",
                    DuplicateSessionError, target="session_id",
                )
            record_id = self._next_id("ses")
            prev = _GENESIS if not self._sessions else self._prev(
                list(self._sessions.values()))
            record = SessionRecord(
                record_id=record_id,
                session_id=session_id,
                page=page,
                attributes=attrs,
                seq=seq,
                prev_digest=prev,
                digest=_pin(_session_payload(
                    record_id, session_id, page, attrs, seq, prev)),
            )
            self._sessions[session_id] = record
            self._session_state[session_id] = STATE_ACTIVE
            self._audit_event(
                KIND_SESSION_STARTED, seq, record_id=record_id,
                session_id=session_id, digest=record.digest,
            )
            return record

    def end_session(self, session_id: str, seq: int) -> SessionEndRecord:
        """Close a session (terminal — double-end refused)."""
        with self._lock:
            self._claim_seq(seq)
            _check_id(session_id, "session_id")
            if session_id not in self._sessions:
                raise self._reject(
                    seq, f"unknown session {session_id!r}",
                    UnknownSessionError, target="session_id")
            if self._session_state[session_id] != STATE_ACTIVE:
                raise self._reject(
                    seq, f"session {session_id!r} is not active",
                    SessionStateError, target="session_id")
            record_id = self._next_id("end")
            prev = self._sessions[session_id].digest
            record = SessionEndRecord(
                record_id=record_id,
                session_id=session_id,
                seq=seq,
                prev_digest=prev,
                digest=_pin(_end_payload(record_id, session_id, seq, prev)),
            )
            self._session_state[session_id] = STATE_ENDED
            self._audit_event(
                KIND_SESSION_ENDED, seq, record_id=record_id,
                session_id=session_id, digest=record.digest,
            )
            return record

    # -- vitals -----------------------------------------------------------

    def vital(
        self,
        session_id: str,
        metric: str,
        value: float,
        seq: int,
        url: str | None = None,
    ) -> VitalSample:
        """Record one web-vital sample for a live session.

        The rating is computed from the pinned thresholds and stored as
        data. Values are rounded to 6 decimal places on ingest.
        """
        with self._lock:
            self._claim_seq(seq)
            _check_id(session_id, "session_id")
            _check_metric(metric)
            canonical_value = _check_value(metric, value)
            url = _check_url(url)
            if session_id not in self._sessions:
                raise self._reject(
                    seq, f"unknown session {session_id!r}",
                    UnknownSessionError, target="session_id")
            if self._session_state[session_id] != STATE_ACTIVE:
                raise self._reject(
                    seq, f"session {session_id!r} is not active",
                    SessionStateError, target="session_id")
            record_id = self._next_id("vtl")
            prev = self._prev(self._samples)
            rating = _rate(metric, canonical_value)
            sample = VitalSample(
                record_id=record_id,
                session_id=session_id,
                metric=metric,
                value=canonical_value,
                rating=rating,
                url=url,
                seq=seq,
                prev_digest=prev,
                digest=_pin(_sample_payload(
                    record_id, session_id, metric, canonical_value, rating,
                    url, seq, prev)),
            )
            self._samples.append(sample)
            self._by_metric.setdefault(metric, []).append(sample)
            self._audit_event(
                KIND_VITAL_RECORDED, seq, record_id=record_id,
                session_id=session_id, metric=metric, rating=rating,
                digest=sample.digest,
            )
            return sample

    # -- alerts -----------------------------------------------------------

    def alert(
        self,
        alert_id: str,
        metric: str,
        seq: int,
        poor_fraction_threshold: float,
        window: int = 100,
        severity: str = SEVERITY_WARNING,
    ) -> AlertRule:
        """Define a poor-fraction alert rule over the trailing window.

        The rule fires when the fraction of ``poor`` samples among the
        most recent ``window`` samples for ``metric`` is >=
        ``poor_fraction_threshold``.
        """
        with self._lock:
            self._claim_seq(seq)
            _check_id(alert_id, "alert_id")
            _check_metric(metric)
            threshold = _check_threshold(poor_fraction_threshold)
            window = _check_window(window)
            _check_severity(severity)
            if alert_id in self._alerts:
                raise self._reject(
                    seq, f"duplicate alert id {alert_id!r}",
                    DuplicateAlertError, target="alert_id")
            record_id = self._next_id("alr")
            prev = _GENESIS if not self._alerts else self._prev(
                list(self._alerts.values()))
            rule = AlertRule(
                record_id=record_id,
                alert_id=alert_id,
                metric=metric,
                poor_fraction_threshold=threshold,
                window=window,
                severity=severity,
                seq=seq,
                prev_digest=prev,
                digest=_pin(_alert_payload(
                    record_id, alert_id, metric, threshold, window,
                    severity, seq, prev)),
            )
            self._alerts[alert_id] = rule
            self._audit_event(
                KIND_ALERT_DEFINED, seq, record_id=record_id,
                alert_id=alert_id, metric=metric, severity=severity,
                digest=rule.digest,
            )
            return rule

    def evaluate(self, seq: int) -> AlertEvaluation:
        """Book one evaluation of every alert rule.

        Verdicts are data: no rules or no samples evaluate to ``triggered``
        ``False`` with zero counts, never an exception.
        """
        with self._lock:
            self._claim_seq(seq)
            verdicts: list[RuleVerdict] = []
            for alert_id in sorted(self._alerts):
                rule = self._alerts[alert_id]
                window = self._by_metric.get(rule.metric, [])[-rule.window:]
                n = len(window)
                poor = sum(1 for s in window if s.rating == RATING_POOR)
                fraction = round(poor / n, 6) if n else 0.0
                verdicts.append(RuleVerdict(
                    alert_id=alert_id,
                    metric=rule.metric,
                    triggered=n > 0 and fraction >= rule.poor_fraction_threshold,
                    poor_fraction=fraction,
                    window_samples=n,
                    threshold=rule.poor_fraction_threshold,
                ))
            verdicts_t = tuple(verdicts)
            record_id = self._next_id("evl")
            prev = self._prev(self._samples)
            evaluation = AlertEvaluation(
                record_id=record_id,
                verdicts=verdicts_t,
                seq=seq,
                prev_digest=prev,
                digest=_pin(_eval_payload(record_id, verdicts_t, seq, prev)),
            )
            self._audit_event(
                KIND_ALERT_EVALUATED, seq, record_id=record_id,
                rule_count=len(verdicts_t),
                triggered=[v.alert_id for v in verdicts_t if v.triggered],
                digest=evaluation.digest,
            )
            return evaluation

    # -- summary ----------------------------------------------------------

    def summary(self, metric: str, seq: int) -> MetricSummary:
        """Book a per-metric rollup: rating counts, poor fraction, median."""
        with self._lock:
            self._claim_seq(seq)
            _check_metric(metric)
            samples = self._by_metric.get(metric, [])
            counts = {r: 0 for r in RATINGS}
            for s in samples:
                counts[s.rating] += 1
            total = len(samples)
            poor_fraction = (
                round(counts[RATING_POOR] / total, 6) if total else 0.0
            )
            median: float | None = None
            if samples:
                ordered = sorted(s.value for s in samples)
                mid = total // 2
                if total % 2:
                    median = ordered[mid]
                else:
                    median = round((ordered[mid - 1] + ordered[mid]) / 2, 6)
            record_id = self._next_id("sum")
            prev = self._prev(self._samples)
            report = MetricSummary(
                record_id=record_id,
                metric=metric,
                counts=counts,
                total=total,
                poor_fraction=poor_fraction,
                median=median,
                seq=seq,
                prev_digest=prev,
                digest=_pin(_summary_payload(
                    record_id, metric, counts, total, poor_fraction,
                    median, seq, prev)),
            )
            self._audit_event(
                KIND_SUMMARY_REPORTED, seq, record_id=record_id,
                metric=metric, total=total, poor_fraction=poor_fraction,
                digest=report.digest,
            )
            return report

    # -- views ------------------------------------------------------------

    def get_session(self, session_id: str) -> SessionRecord:
        """Fetch a session record by id (raises on unknown)."""
        with self._lock:
            if session_id not in self._sessions:
                raise UnknownSessionError(
                    f"unknown session {session_id!r}")
            return self._sessions[session_id]

    def session_state(self, session_id: str) -> str:
        """Current lifecycle state of a session (``active``/``ended``)."""
        with self._lock:
            if session_id not in self._session_state:
                raise UnknownSessionError(
                    f"unknown session {session_id!r}")
            return self._session_state[session_id]

    def session_ids(self) -> tuple:
        """All registered session ids in registration order."""
        with self._lock:
            return tuple(self._sessions)

    def get_sample(self, record_id: str) -> VitalSample:
        """Fetch a vital sample by record id (raises on unknown)."""
        with self._lock:
            for sample in self._samples:
                if sample.record_id == record_id:
                    return sample
            raise RUMError(f"unknown sample {record_id!r}")

    def get_alert(self, alert_id: str) -> AlertRule:
        """Fetch an alert rule by id (raises on unknown)."""
        with self._lock:
            if alert_id not in self._alerts:
                raise UnknownAlertError(f"unknown alert {alert_id!r}")
            return self._alerts[alert_id]

    def sample_ids(self, metric: str | None = None) -> tuple:
        """Sample record ids, optionally filtered to one metric."""
        with self._lock:
            if metric is None:
                return tuple(s.record_id for s in self._samples)
            _check_metric(metric)
            return tuple(s.record_id for s in self._by_metric.get(metric, ()))

    def stats(self) -> Mapping[str, Any]:
        """Ledger counters (no user data)."""
        with self._lock:
            return {
                "sessions": len(self._sessions),
                "samples": len(self._samples),
                "alerts": len(self._alerts),
                "last_seq": self._last_seq,
                "threshold_digest": _THRESHOLD_DIGEST,
                "module_version": RUM_MONITOR_VERSION,
            }

    def audit_log(self) -> tuple:
        """Append-only audit events in seq order."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    monitor = RUMMonitor()
    session = monitor.session("s-1", 1, page="/home")
    assert session.verify() and session.record_id == "ses-1"
    good = monitor.vital("s-1", "lcp", 2400.0, 2)
    assert good.rating == "good" and good.verify()
    ni = monitor.vital("s-1", "lcp", 3000.0, 3)
    assert ni.rating == "needs-improvement"
    poor = monitor.vital("s-1", "lcp", 5000.0, 4)
    assert poor.rating == "poor"
    cls = monitor.vital("s-1", "cls", 0.08, 5)
    assert cls.rating == "good"
    rule = monitor.alert("a-1", "lcp", 6, 0.5, window=10)
    assert rule.verify()
    evaluation = monitor.evaluate(7)
    assert len(evaluation.verdicts) == 1
    assert not evaluation.verdicts[0].triggered
    assert evaluation.verify()
    summary = monitor.summary("lcp", 8)
    assert summary.counts == {
        "good": 1, "needs-improvement": 1, "poor": 1}, summary.counts
    assert summary.total == 3 and summary.median == 3000.0
    assert summary.verify()
    ended = monitor.end_session("s-1", 9)
    assert ended.verify() and monitor.session_state("s-1") == "ended"
    assert monitor.stats()["sessions"] == 1
    assert monitor.stats()["samples"] == 4
    assert monitor.stats()["alerts"] == 1
    print("rum-monitor OK: session, vital, alert, evaluate, summary, pins")


if __name__ == "__main__":
    main()


__all__ = [
    "RUM_MONITOR_VERSION",
    "RUM_MONITOR_SCHEMA",
    "AUDIT_SCHEMA",
    "KIND_SESSION_STARTED",
    "KIND_SESSION_ENDED",
    "KIND_VITAL_RECORDED",
    "KIND_ALERT_DEFINED",
    "KIND_ALERT_EVALUATED",
    "KIND_SUMMARY_REPORTED",
    "KIND_REJECTED",
    "METRIC_LCP",
    "METRIC_INP",
    "METRIC_CLS",
    "METRIC_FCP",
    "METRIC_TTFB",
    "METRICS",
    "RATING_GOOD",
    "RATING_NEEDS_IMPROVEMENT",
    "RATING_POOR",
    "RATINGS",
    "SEVERITIES",
    "STATE_ACTIVE",
    "STATE_ENDED",
    "RUMError",
    "SeqOrderError",
    "UnknownSessionError",
    "DuplicateSessionError",
    "SessionStateError",
    "UnknownMetricError",
    "BadValueError",
    "DuplicateAlertError",
    "UnknownAlertError",
    "BadAlertError",
    "SessionRecord",
    "SessionEndRecord",
    "VitalSample",
    "AlertRule",
    "RuleVerdict",
    "AlertEvaluation",
    "MetricSummary",
    "RUMMonitor",
    "rum_monitor_audit_event",
    "main",
]
