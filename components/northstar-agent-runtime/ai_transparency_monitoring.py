"""AI transparency monitoring: transparency-signal monitor/alert decision ledger, Simulated.

Research note: transparency monitoring is the AI transparency sense layer - the
host declares which deployed systems are transparency-watched, over which
pinned transparency-signal vocabulary, against which declared thresholds,
and declares which transparency alerts were raised when observations were
declared to breach them. This module is the *decision ledger* for
declared AI transparency monitoring: which transparency-watched targets had
which transparency watches booked (over a pinned transparency-signal
vocabulary with declared thresholds), what declared transparency alerts
were booked against them (with declared transparency-concern kinds and
alert-level vocabulary), and what transparency posture the ledger derives -
defensible bookkeeping, never proof that the real world was
transparency-watched, that an alert was really warranted, or that anyone
responded.

This module owns the monitor -> alert -> verify lifecycle:

* **monitor()** - book one declared transparency watch (minted ``twt-N``
  ids; pinned transparency-signal vocabulary; declared threshold as data;
  declared check cadence); the first monitor registers its
  transparency-watched target; raw transparency-signal streams,
  thresholds' provenance, disclosure texts, and raw alert payloads never
  enter records - digest pins only.
* **alert()** - book one declared transparency alert (minted ``tal-N``
  ids; pinned transparency-concern-kind vocabulary; pinned alert-level
  vocabulary; declared observed value as data); chainable; fail-closed
  on unknown or retired targets.
* **verify()** - **pure read**: re-derive one watch or alert record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the observation really happened.
* **evaluate()** - **pure read**: derive one target's
  transparency-monitoring posture as data
  (``transparency-critical-firing`` -> ``transparency-firing`` ->
  ``transparency-warned`` -> ``transparency-covered`` ->
  ``transparency-quiet``) with watch/alert tallies and a digest-pinned
  integrity flag.
* **retire()** - terminal retirement of a transparency-watched target id;
  ids are never recycled.

Distinct-layer rationale vs siblings: ``ai_monitoring.py`` owns general
operational metric watches (error-rate, latency-p99, throughput) - this
module owns *transparency-signal* watches over a pinned transparency
vocabulary; ``ai_safety_monitoring.py`` owns *safety-signal* watches
over a pinned safety vocabulary; ``ai_ethics_monitoring.py`` owns
*ethics-signal* watches over a pinned ethics vocabulary;
``ai_fairness_monitoring.py`` owns *fairness-signal* watches over a
pinned fairness vocabulary; ``ai_transparency.py`` owns the
transparency-disclosure ledger (declared disclosures over the
transparency artifact vocabulary); ``ai_surveillance.py`` owns declared
behavior surveillance observations; ``ai_oversight.py`` owns declared
oversight sessions - this module is the *transparency-monitoring
decision* lifecycle none of them own: declared transparency watches with
declared thresholds, declared transparency-concern-kind alerts, digest
re-derivation, and the ledger-rule posture that turns declared
transparency watches and alerts into a transparency-monitoring claim,
always as data, never as measured transparency truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-transparency-monitoring.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module transparency-monitors nothing, detects nothing
real, and proves nothing about real-world behavior. A booked
``transparency-critical-firing`` posture means "the host declared it",
never "a real transparency alert fired"; a booked ``resolved`` alert
means "the host declared it", never "the real cause was found".
Transparency-signal streams, raw observations, alert payloads,
disclosure texts, model cards, datasheets, explanation material,
operator identities, and runbook contents never enter records or cross
the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_TRANSPARENCY_MONITORING_VERSION = "ai-transparency-monitoring.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-transparency-monitoring.v1"

#: Pinned transparency-signal vocabulary (booked as data).
TRANSPARENCY_SIGNALS = (
    "disclosure-coverage-rate",
    "documentation-completeness-rate",
    "explainability-score",
    "decision-traceability-rate",
    "model-card-coverage-rate",
    "datasheet-coverage-rate",
    "audit-trail-completeness-rate",
    "user-notification-rate",
    "redress-path-availability-rate",
    "capability-disclosure-rate",
)

#: Pinned watch-cadence vocabulary (declared cadence, as data).
WATCH_CADENCES = (
    "realtime",
    "minute",
    "hourly",
    "daily",
)

#: Pinned transparency-concern-kind vocabulary (booked as data, never proof a
#: transparency concern really occurred).
CONCERN_KINDS = (
    "missing-disclosure",
    "undocumented-capability",
    "opaque-decision",
    "unexplained-outcome",
    "missing-model-card",
    "missing-datasheet",
    "inadequate-notification",
    "audit-trail-gap",
)

#: Pinned alert-level vocabulary (booked as data, never proof of real
#: severity).
ALERT_LEVELS = (
    "info",
    "warning",
    "critical",
)

#: Pinned alert-status vocabulary (booked as data).
ALERT_STATUSES = (
    "firing",
    "acknowledged",
    "resolved",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data), with precedence order
#: transparency-critical-firing > transparency-firing > transparency-warned >
#: transparency-covered > transparency-quiet.
POSTURES = (
    "unmonitored",
    "transparency-critical-firing",
    "transparency-firing",
    "transparency-warned",
    "transparency-covered",
    "transparency-quiet",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "monitored",
    "alerted",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "telemetry_stream",
        "metric_stream",
        "metric_values",
        "raw_observations",
        "observations",
        "observation",
        "observed_timeseries",
        "reading",
        "readings",
        "sample",
        "samples",
        "timeseries",
        "time_series",
        "series",
        "payload",
        "alert_payload",
        "alert_body",
        "alert_message",
        "alert_text",
        "notification",
        "runbook",
        "runbook_contents",
        "playbook",
        "operator",
        "operator_id",
        "operator_identity",
        "oncall",
        "responder",
        "threshold_provenance",
        "provenance",
        "screenshot",
        "snapshot",
        "dump",
        "dumps",
        "recording",
        "heartbeat",
        "evidence",
        "forensics",
        "root_cause",
        "causal_chain",
        "impact",
        "impact_narrative",
        "incident",
        "incident_description",
        "report",
        "report_text",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "personal_data",
        "identity",
        "output",
        "outputs",
        "response",
        "responses",
        "prompt",
        "prompts",
        "command_output",
        "stderr",
        "stdout",
        "disclosure_text",
        "disclosure_texts",
        "disclosure_material",
        "disclosure_content",
        "disclosure_report",
        "model_card",
        "model_cards",
        "datasheet",
        "datasheets",
        "system_card",
        "system_cards",
        "explanation",
        "explanations",
        "explanation_material",
        "decision_record",
        "decision_records",
        "decision_justification",
        "traceability_log",
        "transparency_report",
        "transparency_analysis",
        "transparency_audit",
        "transparency_case",
        "transparency_metric_stream",
        "transparency_threshold_provenance",
        "documentation",
        "documentation_text",
        "audit_trail",
        "audit_trail_entries",
        "user_notice",
        "user_notification",
        "notification_text",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AITransparencyMonitoringError(Exception):
    """Base class for all ai-transparency-monitoring ledger errors."""


class BadTargetError(AITransparencyMonitoringError):
    pass


class UnknownTargetError(AITransparencyMonitoringError):
    pass


class RetiredTargetError(AITransparencyMonitoringError):
    pass


class BadSignalError(AITransparencyMonitoringError):
    pass


class BadCadenceError(AITransparencyMonitoringError):
    pass


class BadThresholdError(AITransparencyMonitoringError):
    pass


class BadConcernKindError(AITransparencyMonitoringError):
    pass


class BadLevelError(AITransparencyMonitoringError):
    pass


class BadStatusError(AITransparencyMonitoringError):
    pass


class BadObservedError(AITransparencyMonitoringError):
    pass


class BadDigestError(AITransparencyMonitoringError):
    pass


class BadReasonError(AITransparencyMonitoringError):
    pass


class UnknownRecordError(AITransparencyMonitoringError):
    pass


class SeqOrderError(AITransparencyMonitoringError):
    pass


class AuditKindError(AITransparencyMonitoringError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadTargetError(f"{what} must be a non-empty string")
    return value


def _check_signal(value: Any) -> str:
    if value not in TRANSPARENCY_SIGNALS:
        raise BadSignalError(f"transparency_signal must be one of {TRANSPARENCY_SIGNALS}")
    return value


def _check_cadence(value: Any) -> str:
    if value not in WATCH_CADENCES:
        raise BadCadenceError(f"cadence must be one of {WATCH_CADENCES}")
    return value


def _check_threshold(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadThresholdError("threshold must be a number")
    return float(value)


def _check_concern_kind(value: Any) -> str:
    if value not in CONCERN_KINDS:
        raise BadConcernKindError(f"concern_kind must be one of {CONCERN_KINDS}")
    return value


def _check_level(value: Any) -> str:
    if value not in ALERT_LEVELS:
        raise BadLevelError(f"level must be one of {ALERT_LEVELS}")
    return value


def _check_status(value: Any) -> str:
    if value not in ALERT_STATUSES:
        raise BadStatusError(f"status must be one of {ALERT_STATUSES}")
    return value


def _check_observed(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadObservedError("observed_value must be a number")
    return float(value)


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransparencyWatch:
    watch_id: str
    target_id: str
    seq: int
    transparency_signal: str
    threshold: float
    cadence: str
    config_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _watch_payload(self), "ai-transparency-monitoring.monitor"
        )


@dataclass(frozen=True)
class TransparencyAlert:
    alert_id: str
    target_id: str
    seq: int
    concern_kind: str
    level: str
    observed_value: float
    status: str
    alert_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _alert_payload(self), "ai-transparency-monitoring.alert"
        )


@dataclass(frozen=True)
class RetireRecord:
    target_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-transparency-monitoring.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-transparency-monitoring.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    target_id: str
    seq: int
    posture: str
    n_watches: int
    n_alerts: int
    n_firing: int
    n_critical: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-transparency-monitoring.evaluate"
        )


def _watch_payload(rec: "TransparencyWatch") -> Dict[str, Any]:
    return {
        "watch_id": rec.watch_id,
        "target_id": rec.target_id,
        "seq": rec.seq,
        "transparency_signal": rec.transparency_signal,
        "threshold": rec.threshold,
        "cadence": rec.cadence,
        "config_digest": rec.config_digest,
    }


def _alert_payload(rec: "TransparencyAlert") -> Dict[str, Any]:
    return {
        "alert_id": rec.alert_id,
        "target_id": rec.target_id,
        "seq": rec.seq,
        "concern_kind": rec.concern_kind,
        "level": rec.level,
        "observed_value": rec.observed_value,
        "status": rec.status,
        "alert_digest": rec.alert_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"target_id": rec.target_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "target_id": rep.target_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_watches": rep.n_watches,
        "n_alerts": rep.n_alerts,
        "n_firing": rep.n_firing,
        "n_critical": rep.n_critical,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_transparency_monitoring_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AITransparencyMonitoringError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-transparency-monitoring",
        "version": AI_TRANSPARENCY_MONITORING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AITransparencyMonitoring:
    """AI transparency-monitoring monitor/alert decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All thresholds, observed
    values, transparency-concern kinds, levels, and postures are booked as
    data - never proof that real transparency monitoring happened or that
    an alert was really warranted.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._watches: Dict[str, TransparencyWatch] = {}
        self._alerts: Dict[str, TransparencyAlert] = {}
        self._target_watches: Dict[str, List[str]] = {}
        self._target_alerts: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._watch_counter = 0
        self._alert_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_transparency_monitoring_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-transparency-monitoring",
                "version": AI_TRANSPARENCY_MONITORING_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_transparency_monitoring_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, target_id: str) -> None:
        if target_id in self._retired:
            raise RetiredTargetError(f"target is retired: {target_id!r}")

    # -- mutations ---------------------------------------------------------

    def monitor(
        self,
        target_id: str,
        seq: int,
        transparency_signal: str = "disclosure-coverage-rate",
        threshold: float = 0.0,
        cadence: str = "minute",
        config_digest: str = "",
    ) -> TransparencyWatch:
        """Book one declared transparency watch (minted ``twt-N`` id).

        The first monitor on an id registers the transparency-watched
        target. Raw transparency-signal streams, thresholds' provenance,
        disclosure texts, and operator identities never enter records -
        digest pins only. Fail-closed: failed mutations consume their seq
        and book an ``ai-transparency-monitoring.rejected`` row; rewinds
        raise bare.
        """
        with self._lock:
            try:
                target_id = _check_id(target_id, "target_id")
                self._require_seq(seq)
                transparency_signal = _check_signal(transparency_signal)
                threshold = _check_threshold(threshold)
                cadence = _check_cadence(cadence)
                config_digest = _check_digest(config_digest, "config_digest")
                self._require_live(target_id)
            except AITransparencyMonitoringError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._watch_counter += 1
            watch_id = f"twt-{self._watch_counter}"
            provisional = TransparencyWatch(
                watch_id=watch_id,
                target_id=target_id,
                seq=seq,
                transparency_signal=transparency_signal,
                threshold=threshold,
                cadence=cadence,
                config_digest=config_digest,
                digest="",
            )
            digest = _digest_pin(
                _watch_payload(provisional), "ai-transparency-monitoring.monitor"
            )
            rec = TransparencyWatch(
                watch_id=watch_id,
                target_id=target_id,
                seq=seq,
                transparency_signal=transparency_signal,
                threshold=threshold,
                cadence=cadence,
                config_digest=config_digest,
                digest=digest,
            )
            self._watches[watch_id] = rec
            self._target_watches.setdefault(target_id, []).append(watch_id)
            self._emit(
                "monitored",
                seq,
                watch_id=watch_id,
                target_id=target_id,
                transparency_signal=transparency_signal,
                threshold=threshold,
                cadence=cadence,
                config_digest=config_digest,
            )
            return rec

    def alert(
        self,
        target_id: str,
        seq: int,
        concern_kind: str = "missing-disclosure",
        level: str = "warning",
        observed_value: float = 0.0,
        status: str = "firing",
        alert_digest: str = "",
    ) -> TransparencyAlert:
        """Book one declared transparency alert (minted ``tal-N`` id).

        Repeatable chain: many alerts may be booked against one target.
        The observed value, transparency-concern kind, and level are booked
        as data, never as proof the observation really happened or that
        the level was warranted. Fail-closed on unknown or retired
        targets.
        """
        with self._lock:
            try:
                target_id = _check_id(target_id, "target_id")
                self._require_seq(seq)
                concern_kind = _check_concern_kind(concern_kind)
                level = _check_level(level)
                observed_value = _check_observed(observed_value)
                status = _check_status(status)
                alert_digest = _check_digest(alert_digest, "alert_digest")
                self._require_live(target_id)
                if target_id not in self._target_watches:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
            except AITransparencyMonitoringError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._alert_counter += 1
            alert_id = f"tal-{self._alert_counter}"
            provisional = TransparencyAlert(
                alert_id=alert_id,
                target_id=target_id,
                seq=seq,
                concern_kind=concern_kind,
                level=level,
                observed_value=observed_value,
                status=status,
                alert_digest=alert_digest,
                digest="",
            )
            digest = _digest_pin(
                _alert_payload(provisional), "ai-transparency-monitoring.alert"
            )
            rec = TransparencyAlert(
                alert_id=alert_id,
                target_id=target_id,
                seq=seq,
                concern_kind=concern_kind,
                level=level,
                observed_value=observed_value,
                status=status,
                alert_digest=alert_digest,
                digest=digest,
            )
            self._alerts[alert_id] = rec
            self._target_alerts.setdefault(target_id, []).append(alert_id)
            self._emit(
                "alerted",
                seq,
                alert_id=alert_id,
                target_id=target_id,
                concern_kind=concern_kind,
                level=level,
                observed_value=observed_value,
                status=status,
                alert_digest=alert_digest,
            )
            return rec

    def retire(self, target_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminal retirement of a transparency-watched target id; ids are never recycled."""
        with self._lock:
            try:
                target_id = _check_id(target_id, "target_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if target_id in self._retired:
                    raise RetiredTargetError(f"target is retired: {target_id!r}")
                if target_id not in self._target_watches:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
            except AITransparencyMonitoringError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                target_id=target_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-transparency-monitoring.retire"
            )
            rec = RetireRecord(
                target_id=target_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[target_id] = rec
            self._emit("retired", seq, target_id=target_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one watch or alert record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the observation really happened. Seq is shape-validated
        only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            rec = self._watches.get(record_id)
            if rec is None:
                rec = self._alerts.get(record_id)
            if rec is None or isinstance(record_id, bool) or not isinstance(
                record_id, str
            ):
                raise UnknownRecordError(f"unknown record id: {record_id!r}")
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-transparency-monitoring.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, target_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one target's transparency-monitoring posture as data.

        Posture by ledger rule: ``transparency-critical-firing`` (any
        critical-level alert with status firing) ->
        ``transparency-firing`` (any firing alert) -> ``transparency-warned``
        (any acknowledged alert, or any non-resolved alert left over) ->
        ``transparency-covered`` (watches booked and every alert resolved)
        -> ``transparency-quiet`` (watches booked, no alerts ever).
        ``integrity_ok`` re-derives all in-scope digest pins as data. Seq
        is shape-validated only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            target_id = _check_id(target_id, "target_id")
            if target_id not in self._target_watches:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            watch_ids = self._target_watches[target_id]
            watches = [self._watches[i] for i in watch_ids]
            alert_ids = self._target_alerts.get(target_id, [])
            alerts = [self._alerts[i] for i in alert_ids]
            n_firing = sum(1 for a in alerts if a.status == "firing")
            n_critical = sum(
                1 for a in alerts if a.level == "critical" and a.status == "firing"
            )
            if n_critical > 0:
                posture = "transparency-critical-firing"
            elif n_firing > 0:
                posture = "transparency-firing"
            elif any(a.status == "acknowledged" for a in alerts):
                posture = "transparency-warned"
            elif alerts and all(a.status == "resolved" for a in alerts):
                posture = "transparency-covered"
            else:
                posture = "transparency-quiet"
            integrity_ok = all(w.verify() for w in watches) and all(
                a.verify() for a in alerts
            )
            provisional = EvaluationReport(
                target_id=target_id,
                seq=seq,
                posture=posture,
                n_watches=len(watches),
                n_alerts=len(alerts),
                n_firing=n_firing,
                n_critical=n_critical,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional),
                "ai-transparency-monitoring.evaluate",
            )
            return EvaluationReport(
                target_id=target_id,
                seq=seq,
                posture=posture,
                n_watches=len(watches),
                n_alerts=len(alerts),
                n_firing=n_firing,
                n_critical=n_critical,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def watch_record(self, watch_id: str, seq: int) -> TransparencyWatch:
        with self._lock:
            self._check_read_seq(seq)
            if watch_id not in self._watches:
                raise UnknownRecordError(f"unknown watch id: {watch_id!r}")
            return self._watches[watch_id]

    def alert_record(self, alert_id: str, seq: int) -> TransparencyAlert:
        with self._lock:
            self._check_read_seq(seq)
            if alert_id not in self._alerts:
                raise UnknownRecordError(f"unknown alert id: {alert_id!r}")
            return self._alerts[alert_id]

    def watches_for(self, target_id: str, seq: int) -> Tuple[TransparencyWatch, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._watches[i] for i in self._target_watches.get(target_id, []))

    def alerts_for(self, target_id: str, seq: int) -> Tuple[TransparencyAlert, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._alerts[i] for i in self._target_alerts.get(target_id, []))

    def target_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._target_watches))

    def watch_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._watches))

    def alert_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._alerts))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_targets": len(self._target_watches),
                "n_watches": len(self._watches),
                "n_alerts": len(self._alerts),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_TRANSPARENCY_MONITORING_VERSION,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._audit)


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: exercise monitor -> alert -> verify -> evaluate."""
    ledger = AITransparencyMonitoring()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.monitor(
        "target-1", 1, transparency_signal="disclosure-coverage-rate",
        threshold=0.9, cadence="minute"
    )
    assert rec.verify()
    alr = ledger.alert(
        "target-1", 2, concern_kind="missing-disclosure", level="warning",
        observed_value=0.62
    )
    assert alr.verify()
    rep = ledger.verify(rec.watch_id, 3)
    assert rep.verdict == "verified"
    rep2 = ledger.verify(alr.alert_id, 4)
    assert rep2.verdict == "verified"
    ev = ledger.evaluate("target-1", 5)
    assert ev.posture == "transparency-firing"
    ret = ledger.retire("target-1", 6)
    assert ret.verify()
    print(
        "ai-transparency-monitoring OK: monitor, alert, verify, evaluate, "
        "retire, pins, audit"
    )


if __name__ == "__main__":
    main()
