"""AI ethics monitoring: ethics-signal monitor/alert decision ledger, Simulated.

Research note: ethics monitoring is the AI ethics sense layer - the host
declares which deployed systems are ethics-watched, over which pinned
ethics-signal vocabulary, against which declared thresholds, and declares
which ethics alerts were raised when observations were declared to breach
them. This module is the *decision ledger* for declared AI ethics
monitoring: which ethics-watched targets had which ethics watches booked
(over a pinned ethics-signal vocabulary with declared thresholds), what
declared ethics alerts were booked against them (with declared ethics-
concern kinds and alert-level vocabulary), and what ethics posture the
ledger derives - defensible bookkeeping, never proof that the real world
was ethics-watched, that an alert was really warranted, or that anyone
responded.

This module owns the monitor -> alert -> verify lifecycle:

* **monitor()** - book one declared ethics watch (minted ``ewt-N`` ids;
  pinned ethics-signal vocabulary; declared threshold as data; declared
  check cadence); the first monitor registers its ethics-watched target;
  raw ethics-signal streams, thresholds' provenance, operator identities,
  and raw alert payloads never enter records - digest pins only.
* **alert()** - book one declared ethics alert (minted ``eal-N`` ids;
  pinned ethics-concern-kind vocabulary; pinned alert-level vocabulary;
  declared observed value as data); chainable; fail-closed on unknown or
  retired targets.
* **verify()** - **pure read**: re-derive one watch or alert record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the observation really happened.
* **evaluate()** - **pure read**: derive one target's ethics-monitoring
  posture as data (``ethics-critical-firing`` -> ``ethics-firing`` ->
  ``ethics-warned`` -> ``ethics-covered`` -> ``ethics-quiet``) with
  watch/alert tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of an ethics-watched target id; ids
  are never recycled.

Distinct-layer rationale vs siblings: ``ai_monitoring.py`` owns general
operational metric watches (error-rate, latency-p99, throughput) - this
module owns *ethics-signal* watches over a pinned ethics vocabulary;
``ai_safety_monitoring.py`` owns safety-signal watches (harm rates,
refusal rates, policy-violation rates) - this module owns ethics-signal
watches and ethics-concern alerts, never safety hazards; ``ai_ethics.py``
owns the ethics assessment->evaluation lifecycle; ``ai_incident.py``
owns declared incidents and their declared investigations;
``ai_surveillance.py`` owns declared behavior surveillance observations;
``ai_oversight.py`` owns declared oversight sessions - this module is
the *ethics-monitoring decision* lifecycle none of them own: declared
ethics watches with declared thresholds, declared ethics-concern alerts,
digest re-derivation, and the ledger-rule posture that turns declared
ethics watches and alerts into an ethics-monitoring claim, always as
data, never as measured ethics truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-ethics-monitoring.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module ethics-monitors nothing, detects nothing real,
and proves nothing about real-world behavior. A booked
``ethics-critical-firing`` posture means "the host declared it", never
"a real ethics alert fired"; a booked ``resolved`` alert means "the host
declared it", never "the real cause was found". Ethics-signal streams,
raw observations, alert payloads, operator identities, and runbook
contents never enter records or cross the audit boundary - digest pins
only.
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
AI_ETHICS_MONITORING_VERSION = "ai-ethics-monitoring.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-ethics-monitoring.v1"

#: Pinned ethics-signal vocabulary (booked as data).
ETHICS_SIGNALS = (
    "bias-rate",
    "fairness-violation-rate",
    "discrimination-signal-rate",
    "privacy-breach-rate",
    "consent-violation-rate",
    "transparency-deficit-rate",
    "accountability-gap-rate",
    "manipulation-signal-rate",
    "autonomy-undermining-rate",
    "dignity-harm-rate",
)

#: Pinned watch-cadence vocabulary (declared cadence, as data).
WATCH_CADENCES = (
    "realtime",
    "minute",
    "hourly",
    "daily",
)

#: Pinned ethics-concern-kind vocabulary (booked as data, never proof a
#: concern really occurred).
ETHICS_CONCERN_KINDS = (
    "discriminatory-output",
    "privacy-violation",
    "manipulative-behavior",
    "autonomy-undermining",
    "unfair-treatment",
    "transparency-failure",
    "accountability-gap",
    "dignity-harm",
)

#: Pinned alert-level vocabulary (booked as data).
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

#: Pinned retirement reasons (booked as data).
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-positive",
)

#: Audit schema name for all rows this module emits.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Banned raw-material keys: never cross the audit boundary.
_BANNED_AUDIT_KEYS = frozenset(
    {
        # raw ethics material
        "ethics_signal_stream",
        "signal_stream",
        "observations",
        "observed_values",
        "raw_alert_payload",
        "alert_payload",
        "ethics_report",
        "ethics_violation",
        "bias_report",
        "discrimination_report",
        "harm_narrative",
        "victim_identity",
        "affected_group",
        "protected_class",
        "personal_data",
        "pii",
        "consent_record",
        "operator_id",
        "operator_identity",
        "runbook",
        "runbook_contents",
        "playbook",
        "threshold_provenance",
        "model_weights",
        "weights",
        "prompts",
        "prompt",
        "completions",
        "transcript",
        "api_key",
        "secret",
        "password",
        "token",
    }
)

# ---------------------------------------------------------------------------
# Fail-closed error taxonomy
# ---------------------------------------------------------------------------


class AIEthicsMonitoringError(Exception):
    """Base class for all ai_ethics_monitoring failures."""


class BadTargetError(AIEthicsMonitoringError):
    """The target id is malformed (empty or non-string)."""


class BadSignalError(AIEthicsMonitoringError):
    """The ethics signal is not in the pinned vocabulary."""


class BadCadenceError(AIEthicsMonitoringError):
    """The watch cadence is not in the pinned vocabulary."""


class BadThresholdError(AIEthicsMonitoringError):
    """The declared threshold is not a finite non-negative scalar."""


class BadConcernKindError(AIEthicsMonitoringError):
    """The ethics concern kind is not in the pinned vocabulary."""


class BadLevelError(AIEthicsMonitoringError):
    """The alert level is not in the pinned vocabulary."""


class BadStatusError(AIEthicsMonitoringError):
    """The alert status is not in the pinned vocabulary."""


class BadDigestError(AIEthicsMonitoringError):
    """A digest pin is malformed (empty, non-string, or bad shape)."""


class BadReasonError(AIEthicsMonitoringError):
    """The retire reason is not in the pinned vocabulary."""


class UnknownTargetError(AIEthicsMonitoringError):
    """The target id is not registered in this ledger."""


class RetiredTargetError(AIEthicsMonitoringError):
    """The target id has been terminally retired."""


class UnknownRecordError(AIEthicsMonitoringError):
    """No watch or alert record exists under that id."""


class SeqOrderError(AIEthicsMonitoringError):
    """Caller seq is not a strictly-increasing integer claim."""


class AuditKindError(AIEthicsMonitoringError):
    """The requested audit event kind is unknown."""


class AuditKeyError(AIEthicsMonitoringError):
    """A banned raw-material key was passed to the audit builder."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def _sha256_pin(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_bytes(obj: Any) -> bytes:
    blob = _jcs_dumps(obj)
    if isinstance(blob, bytes):
        return blob
    return str(blob).encode("utf-8")


def _record_digest(record: Dict[str, Any]) -> str:
    return _sha256_pin(_canonical_bytes(record))


def _check_digest_shape(digest: str) -> None:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise BadDigestError("digest pin must be a 'sha256:' string")
    body = digest[len("sha256:") :]
    if len(body) != 64 or any(c not in "0123456789abcdef" for c in body):
        raise BadDigestError("digest pin must carry 64 lowercase hex chars")


@dataclass(frozen=True)
class EthicsWatch:
    """One declared ethics watch (minted ``ewt-N``)."""

    record_id: str
    target_id: str
    ethics_signal: str
    threshold: float
    cadence: str
    config_digest: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = AI_ETHICS_MONITORING_VERSION

    def digest(self) -> str:
        return _record_digest(
            {
                "record_id": self.record_id,
                "target_id": self.target_id,
                "ethics_signal": self.ethics_signal,
                "threshold": self.threshold,
                "cadence": self.cadence,
                "config_digest": self.config_digest,
                "seq": self.seq,
                "schema": self.schema,
                "version": self.version,
            }
        )

    def verify(self) -> bool:
        return self.digest() == self._sealed_digest

    _sealed_digest: str = ""


@dataclass(frozen=True)
class EthicsAlert:
    """One declared ethics alert (minted ``eal-N``)."""

    record_id: str
    target_id: str
    concern_kind: str
    level: str
    observed_value: float
    status: str
    alert_digest: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = AI_ETHICS_MONITORING_VERSION

    def digest(self) -> str:
        return _record_digest(
            {
                "record_id": self.record_id,
                "target_id": self.target_id,
                "concern_kind": self.concern_kind,
                "level": self.level,
                "observed_value": self.observed_value,
                "status": self.status,
                "alert_digest": self.alert_digest,
                "seq": self.seq,
                "schema": self.schema,
                "version": self.version,
            }
        )

    def verify(self) -> bool:
        return self.digest() == self._sealed_digest

    _sealed_digest: str = ""


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read digest re-derivation report."""

    record_id: str
    verdict: str  # "verified" | "tampered"
    digest: str
    schema: str = SCHEMA_PIN
    version: str = AI_ETHICS_MONITORING_VERSION


@dataclass(frozen=True)
class EvaluationReport:
    """Pure-read per-target ethics-monitoring posture."""

    target_id: str
    posture: str
    n_watches: int
    n_alerts: int
    firing: int
    acknowledged: int
    resolved: int
    critical_firing: int
    integrity_ok: bool
    digest: str
    schema: str = SCHEMA_PIN
    version: str = AI_ETHICS_MONITORING_VERSION


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of an ethics-watched target."""

    target_id: str
    reason: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = AI_ETHICS_MONITORING_VERSION


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


_AUDIT_KINDS = ("watched", "alerted", "retired", "rejected")


def ai_ethics_monitoring_audit_event(kind: str, seq: int, details: Dict[str, Any]) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds and banned raw-material keys raise.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    if not isinstance(details, dict):
        raise AuditKeyError("audit details must be a dict")
    banned = [k for k in details if k in _BANNED_AUDIT_KEYS]
    if banned:
        raise AuditKeyError(f"banned raw-material keys in audit details: {banned!r}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_ETHICS_MONITORING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIEthicsMonitoring:
    """Declared ethics-monitor/alert decision ledger, Simulated."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._watches: Dict[str, EthicsWatch] = {}
        self._alerts: Dict[str, EthicsAlert] = {}
        self._targets: Dict[str, int] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._audit_log: List[Dict[str, Any]] = []
        self._watch_seq = 0
        self._alert_seq = 0

    # -- seq discipline -----------------------------------------------------

    def _claim_seq(self, seq: Any) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be an int strictly greater than {self._last_seq}"
            )
        self._last_seq = seq

    def _book_rejected(self, seq: int, reason: str) -> None:
        self._audit_log.append(
            ai_ethics_monitoring_audit_event(
                "rejected", seq, {"reason": reason}
            )
        )

    # -- validation ---------------------------------------------------------

    @staticmethod
    def _check_target(target_id: Any) -> str:
        if not isinstance(target_id, str) or not target_id:
            raise BadTargetError("target_id must be a non-empty string")
        return target_id

    @staticmethod
    def _check_threshold(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BadThresholdError("threshold must be a non-negative scalar")
        f = float(value)
        if f < 0 or f != f or f == float("inf"):
            raise BadThresholdError("threshold must be a finite non-negative scalar")
        return f

    @staticmethod
    def _check_scalar(value: Any, what: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BadThresholdError(f"{what} must be a scalar")
        f = float(value)
        if f != f or f == float("inf"):
            raise BadThresholdError(f"{what} must be finite")
        return f

    # -- lifecycle ----------------------------------------------------------

    def monitor(
        self,
        target_id: str,
        seq: int,
        ethics_signal: str = "bias-rate",
        threshold: float = 0.0,
        cadence: str = "minute",
        config_digest: str = "",
    ) -> EthicsWatch:
        """Book one declared ethics watch (minted ``ewt-N``).

        The first monitor registers the ethics-watched target.
        """
        with self._lock:
            try:
                self._check_target(target_id)
                if target_id in self._retired:
                    raise RetiredTargetError(f"target retired: {target_id!r}")
                if ethics_signal not in ETHICS_SIGNALS:
                    raise BadSignalError(f"unknown ethics signal: {ethics_signal!r}")
                if cadence not in WATCH_CADENCES:
                    raise BadCadenceError(f"unknown cadence: {cadence!r}")
                threshold_f = self._check_threshold(threshold)
                if not isinstance(config_digest, str):
                    raise BadDigestError("config_digest must be a string")
                if config_digest:
                    _check_digest_shape(config_digest)
                self._claim_seq(seq)
            except AIEthicsMonitoringError as exc:
                if isinstance(seq, int) and not isinstance(seq, bool) and seq > self._last_seq:
                    self._last_seq = seq
                    self._book_rejected(seq, type(exc).__name__)
                raise
            self._watch_seq += 1
            record_id = f"ewt-{self._watch_seq}"
            watch = EthicsWatch(
                record_id=record_id,
                target_id=target_id,
                ethics_signal=ethics_signal,
                threshold=threshold_f,
                cadence=cadence,
                config_digest=config_digest,
                seq=seq,
            )
            sealed = EthicsWatch(
                record_id=watch.record_id,
                target_id=watch.target_id,
                ethics_signal=watch.ethics_signal,
                threshold=watch.threshold,
                cadence=watch.cadence,
                config_digest=watch.config_digest,
                seq=watch.seq,
            )
            object.__setattr__(sealed, "_sealed_digest", watch.digest())
            self._watches[record_id] = sealed
            self._targets.setdefault(target_id, 0)
            self._targets[target_id] += 1
            self._audit_log.append(
                ai_ethics_monitoring_audit_event(
                    "watched",
                    seq,
                    {
                        "record_id": record_id,
                        "target_id": target_id,
                        "ethics_signal": ethics_signal,
                        "threshold": threshold_f,
                        "cadence": cadence,
                        "config_digest": config_digest,
                    },
                )
            )
            return sealed

    def alert(
        self,
        target_id: str,
        seq: int,
        concern_kind: str = "discriminatory-output",
        level: str = "warning",
        observed_value: float = 0.0,
        status: str = "firing",
        alert_digest: str = "",
    ) -> EthicsAlert:
        """Book one declared ethics alert (minted ``eal-N``)."""
        with self._lock:
            try:
                self._check_target(target_id)
                if target_id in self._retired:
                    raise RetiredTargetError(f"target retired: {target_id!r}")
                if target_id not in self._targets:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
                if concern_kind not in ETHICS_CONCERN_KINDS:
                    raise BadConcernKindError(
                        f"unknown ethics concern kind: {concern_kind!r}"
                    )
                if level not in ALERT_LEVELS:
                    raise BadLevelError(f"unknown alert level: {level!r}")
                if status not in ALERT_STATUSES:
                    raise BadStatusError(f"unknown alert status: {status!r}")
                observed_f = self._check_scalar(observed_value, "observed_value")
                if not isinstance(alert_digest, str):
                    raise BadDigestError("alert_digest must be a string")
                if alert_digest:
                    _check_digest_shape(alert_digest)
                self._claim_seq(seq)
            except AIEthicsMonitoringError as exc:
                if isinstance(seq, int) and not isinstance(seq, bool) and seq > self._last_seq:
                    self._last_seq = seq
                    self._book_rejected(seq, type(exc).__name__)
                raise
            self._alert_seq += 1
            record_id = f"eal-{self._alert_seq}"
            alert = EthicsAlert(
                record_id=record_id,
                target_id=target_id,
                concern_kind=concern_kind,
                level=level,
                observed_value=observed_f,
                status=status,
                alert_digest=alert_digest,
                seq=seq,
            )
            sealed = EthicsAlert(
                record_id=alert.record_id,
                target_id=alert.target_id,
                concern_kind=alert.concern_kind,
                level=alert.level,
                observed_value=alert.observed_value,
                status=alert.status,
                alert_digest=alert.alert_digest,
                seq=alert.seq,
            )
            object.__setattr__(sealed, "_sealed_digest", alert.digest())
            self._alerts[record_id] = sealed
            self._audit_log.append(
                ai_ethics_monitoring_audit_event(
                    "alerted",
                    seq,
                    {
                        "record_id": record_id,
                        "target_id": target_id,
                        "concern_kind": concern_kind,
                        "level": level,
                        "observed_value": observed_f,
                        "status": status,
                        "alert_digest": alert_digest,
                    },
                )
            )
            return sealed

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one watch or alert record's digest pin."""
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int):
                raise SeqOrderError("read seq must be an int (shape only)")
            if not isinstance(record_id, str) or not record_id:
                raise UnknownRecordError("record_id must be a non-empty string")
            record = self._watches.get(record_id) or self._alerts.get(record_id)
            if record is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            digest = record.digest()
            verdict = "verified" if digest == record._sealed_digest else "tampered"
            return VerificationReport(record_id=record_id, verdict=verdict, digest=digest)

    def evaluate(self, target_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one target's ethics-monitoring posture as data."""
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int):
                raise SeqOrderError("read seq must be an int (shape only)")
            self._check_target(target_id)
            watches = [w for w in self._watches.values() if w.target_id == target_id]
            alerts = [a for a in self._alerts.values() if a.target_id == target_id]
            firing = sum(1 for a in alerts if a.status == "firing")
            acknowledged = sum(1 for a in alerts if a.status == "acknowledged")
            resolved = sum(1 for a in alerts if a.status == "resolved")
            critical_firing = sum(
                1 for a in alerts if a.status == "firing" and a.level == "critical"
            )
            if critical_firing:
                posture = "ethics-critical-firing"
            elif firing:
                posture = "ethics-firing"
            elif acknowledged:
                posture = "ethics-warned"
            elif alerts:
                posture = "ethics-covered"
            else:
                posture = "ethics-quiet"
            integrity_ok = all(
                r.digest() == r._sealed_digest for r in list(watches) + list(alerts)
            )
            body = {
                "target_id": target_id,
                "posture": posture,
                "n_watches": len(watches),
                "n_alerts": len(alerts),
                "firing": firing,
                "acknowledged": acknowledged,
                "resolved": resolved,
                "critical_firing": critical_firing,
                "integrity_ok": integrity_ok,
                "schema": SCHEMA_PIN,
                "version": AI_ETHICS_MONITORING_VERSION,
            }
            return EvaluationReport(
                target_id=target_id,
                posture=posture,
                n_watches=len(watches),
                n_alerts=len(alerts),
                firing=firing,
                acknowledged=acknowledged,
                resolved=resolved,
                critical_firing=critical_firing,
                integrity_ok=integrity_ok,
                digest=_record_digest(body),
            )

    def retire(self, target_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminal retirement of an ethics-watched target id."""
        with self._lock:
            try:
                self._check_target(target_id)
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"unknown retire reason: {reason!r}")
                if target_id in self._retired:
                    raise RetiredTargetError(f"target already retired: {target_id!r}")
                if target_id not in self._targets:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
                self._claim_seq(seq)
            except AIEthicsMonitoringError as exc:
                if isinstance(seq, int) and not isinstance(seq, bool) and seq > self._last_seq:
                    self._last_seq = seq
                    self._book_rejected(seq, type(exc).__name__)
                raise
            record = RetireRecord(target_id=target_id, reason=reason, seq=seq)
            self._retired[target_id] = record
            self._audit_log.append(
                ai_ethics_monitoring_audit_event(
                    "retired", seq, {"target_id": target_id, "reason": reason}
                )
            )
            return record

    # -- pure-read views ------------------------------------------------------

    def watch_record(self, record_id: str) -> EthicsWatch:
        with self._lock:
            record = self._watches.get(record_id)
            if record is None:
                raise UnknownRecordError(f"unknown watch: {record_id!r}")
            return record

    def alert_record(self, record_id: str) -> EthicsAlert:
        with self._lock:
            record = self._alerts.get(record_id)
            if record is None:
                raise UnknownRecordError(f"unknown alert: {record_id!r}")
            return record

    def watches_for(self, target_id: str) -> Tuple[EthicsWatch, ...]:
        with self._lock:
            return tuple(w for w in self._watches.values() if w.target_id == target_id)

    def alerts_for(self, target_id: str) -> Tuple[EthicsAlert, ...]:
        with self._lock:
            return tuple(a for a in self._alerts.values() if a.target_id == target_id)

    def target_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._targets))

    def retired_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._retired))

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "n_targets": len(self._targets),
                "n_watches": len(self._watches),
                "n_alerts": len(self._alerts),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit_log),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._audit_log)


# ---------------------------------------------------------------------------
# stdlib-only self-check + main
# ---------------------------------------------------------------------------


def stdlib_only() -> bool:
    """AST self-check: this module imports only the stdlib."""
    import ast

    allowed = {"hashlib", "threading", "dataclasses", "typing", "json", "ast", "__future__"}
    try:
        from canonical_json import jcs_dumps  # type: ignore  # noqa: F401
        allowed.add("canonical_json")
    except Exception:
        pass
    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
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
    led = AIEthicsMonitoring()
    w = led.monitor("sys-1", 1, ethics_signal="bias-rate", threshold=0.05)
    a = led.alert("sys-1", 2, concern_kind="discriminatory-output", level="warning")
    rep = led.verify(w.record_id, 1)
    assert rep.verdict == "verified"
    ev = led.evaluate("sys-1", 1)
    assert ev.posture == "ethics-firing"
    led.retire("sys-1", 3, reason="manual")
    assert stdlib_only()
    print(
        "ai-ethics-monitoring OK: monitor, alert, verify, evaluate, retire, pins, audit"
    )


if __name__ == "__main__":
    main()
