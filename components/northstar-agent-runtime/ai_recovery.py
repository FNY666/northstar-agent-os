"""AI recovery: incident-recovery decision ledger, Simulated.

Research note: AI recovery is the restoration side of AI incident
response - after an AI incident is declared (capability abuse, model
failure, deployment harm, data compromise), what recovery action the
host declared it took (restore capability, roll back deployment, revoke
access, restore checkpoint, restore data, retrain, restore config,
restore service), what outcome it declared, and what recovery posture
the ledger derives for the incident. This module is the *decision
ledger* for declared AI recovery actions: which incidents had which
recovery kinds booked (over a pinned recovery-kind vocabulary), what
outcomes were declared against them, and what recovery posture the
ledger derives - defensible bookkeeping, never proof that any service
was really restored.

This module owns the recover -> verify -> evaluate lifecycle:

* **recover()** - book one declared recovery action (minted ``rcv-N``
  ids; pinned recovery-kind vocabulary over the common recovery
  classes; pinned outcome vocabulary booked *as data*); the first
  recovery on an id registers the incident; raw incident material,
  telemetry, snapshots, weights, and checkpoint data never enter
  records - digest pins only.
* **verify()** - **pure read**: re-derive one recovery record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the recovery really happened.
* **evaluate()** - **pure read**: derive one incident's recovery
  posture as data (``unaddressed`` -> ``unrecoverable`` ->
  ``contested`` -> ``partially-recovered`` -> ``recovered``) with
  outcome tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of an incident id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``disaster_recovery.py`` owns
operational disaster-recovery mechanics (declared backup/restore and
failover targets); ``account_recovery.py`` owns the credential/account
lifecycle; ``ai_safety.py`` owns the safety assessment -> mitigation
lifecycle; ``ai_incident.py`` owns incident declaration/investigation -
this module is the *recovery-operations* ledger none of them own:
declared recovery actions against declared incidents, digest
re-derivation, and the ledger-rule posture that turns declared
recoveries into a recovery claim, always as data, never as measured
restoration.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-recovery.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module restores nothing, rolls back nothing, revokes
nothing, and proves nothing about real-world restoration outcomes. A
booked ``recovered`` posture means "the host declared it", never "the
service is healthy"; a booked ``failed`` outcome means "the host
declared it", never "the recovery truly failed". Incident material,
telemetry, checkpoints, snapshots, weights, and raw recovery artifacts
never enter records or cross the audit boundary - digest pins only.
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
AI_RECOVERY_VERSION = "ai-recovery.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-recovery.v1"

#: Pinned recovery-kind vocabulary (the recovery classes).
RECOVERY_KINDS = (
    "capability-restoration",
    "deployment-rollback",
    "access-revocation",
    "checkpoint-restore",
    "data-restoration",
    "model-retraining",
    "configuration-restore",
    "service-restoration",
)

#: Pinned recovery-outcome vocabulary (booked as data, never proof).
RECOVERY_OUTCOMES = (
    "recovered",
    "partial",
    "failed",
    "inconclusive",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unaddressed",
    "unrecoverable",
    "contested",
    "partially-recovered",
    "recovered",
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
    "recovered",
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
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "checkpoint",
        "checkpoints",
        "backup",
        "backups",
        "restore_point",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "heartbeat",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "findings",
        "report",
        "reports",
        "incident_text",
        "incident_detail",
        "incident_description",
        "postmortem",
        "root_cause",
        "harm",
        "harm_description",
        "damage",
        "damages",
        "remedy_text",
        "password",
        "passwords",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "api_key",
        "api_keys",
        "token",
        "tokens",
        "private_key",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "dataset",
        "datasets",
        "training_data",
        "pii",
        "exploit",
        "exploits",
        "payload",
        "vulnerability_detail",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIRecoveryError(Exception):
    """Base class for all ai-recovery ledger errors."""


class BadIncidentError(AIRecoveryError):
    pass


class UnknownIncidentError(AIRecoveryError):
    pass


class RetiredIncidentError(AIRecoveryError):
    pass


class BadRecoveryKindError(AIRecoveryError):
    pass


class BadOutcomeError(AIRecoveryError):
    pass


class BadDigestError(AIRecoveryError):
    pass


class BadReasonError(AIRecoveryError):
    pass


class UnknownRecoveryError(AIRecoveryError):
    pass


class SeqOrderError(AIRecoveryError):
    pass


class AuditKindError(AIRecoveryError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadIncidentError(f"{what} must be a non-empty string")
    return value


def _check_recovery_kind(value: Any) -> str:
    if value not in RECOVERY_KINDS:
        raise BadRecoveryKindError(f"recovery_kind must be one of {RECOVERY_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in RECOVERY_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {RECOVERY_OUTCOMES}")
    return value


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
class RecoveryRecord:
    recovery_id: str
    incident_id: str
    seq: int
    recovery_kind: str
    outcome: str
    incident_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _recover_payload(self), "ai-recovery.recover"
        )


@dataclass(frozen=True)
class RetireRecord:
    incident_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-recovery.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-recovery.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    incident_id: str
    seq: int
    posture: str
    n_recoveries: int
    n_recovered: int
    n_partial: int
    n_failed: int
    n_inconclusive: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-recovery.evaluate"
        )


def _recover_payload(rec: "RecoveryRecord") -> Dict[str, Any]:
    return {
        "recovery_id": rec.recovery_id,
        "incident_id": rec.incident_id,
        "seq": rec.seq,
        "recovery_kind": rec.recovery_kind,
        "outcome": rec.outcome,
        "incident_digest": rec.incident_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"incident_id": rec.incident_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "incident_id": rep.incident_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_recoveries": rep.n_recoveries,
        "n_recovered": rep.n_recovered,
        "n_partial": rep.n_partial,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_recovery_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIRecoveryError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-recovery",
        "version": AI_RECOVERY_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIRecovery:
    """AI-recovery recovery-action decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that any incident was really recovered.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._recoveries: Dict[str, RecoveryRecord] = {}
        self._incident_recoveries: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._recovery_counter = 0
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
            row = ai_recovery_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-recovery",
                "version": AI_RECOVERY_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_recovery_audit_event(audit_kind, seq, **details))

    def _require_live(self, incident_id: str) -> None:
        if incident_id in self._retired:
            raise RetiredIncidentError(f"incident is retired: {incident_id!r}")

    # -- mutations ---------------------------------------------------------

    def recover(
        self,
        incident_id: str,
        seq: int,
        recovery_kind: str = "capability-restoration",
        outcome: str = "recovered",
        incident_digest: str = "",
    ) -> RecoveryRecord:
        """Book one declared recovery action (minted ``rcv-N`` id).

        The first recovery on an id registers the incident. Raw incident
        material, telemetry, snapshots, checkpoints, and weights never
        enter records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an ``ai-recovery.rejected`` row;
        rewinds raise bare.
        """
        with self._lock:
            try:
                incident_id = _check_id(incident_id, "incident_id")
                self._require_seq(seq)
                recovery_kind = _check_recovery_kind(recovery_kind)
                outcome = _check_outcome(outcome)
                incident_digest = _check_digest(incident_digest, "incident_digest")
                self._require_live(incident_id)
            except AIRecoveryError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._recovery_counter += 1
            recovery_id = f"rcv-{self._recovery_counter}"
            provisional = RecoveryRecord(
                recovery_id=recovery_id,
                incident_id=incident_id,
                seq=seq,
                recovery_kind=recovery_kind,
                outcome=outcome,
                incident_digest=incident_digest,
                digest="",
            )
            digest = _digest_pin(_recover_payload(provisional), "ai-recovery.recover")
            rec = RecoveryRecord(
                recovery_id=recovery_id,
                incident_id=incident_id,
                seq=seq,
                recovery_kind=recovery_kind,
                outcome=outcome,
                incident_digest=incident_digest,
                digest=digest,
            )
            self._recoveries[recovery_id] = rec
            self._incident_recoveries.setdefault(incident_id, []).append(recovery_id)
            self._emit(
                "recovered",
                seq,
                recovery_id=recovery_id,
                incident_id=incident_id,
                recovery_kind=recovery_kind,
                outcome=outcome,
                incident_digest=incident_digest,
            )
            return rec

    def retire(
        self, incident_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of an incident id; ids are never recycled."""
        with self._lock:
            try:
                incident_id = _check_id(incident_id, "incident_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if incident_id in self._retired:
                    raise RetiredIncidentError(f"incident is retired: {incident_id!r}")
                if incident_id not in self._incident_recoveries:
                    raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
            except AIRecoveryError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                incident_id=incident_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-recovery.retire")
            rec = RetireRecord(
                incident_id=incident_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[incident_id] = rec
            self._emit("retired", seq, incident_id=incident_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, recovery_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one recovery record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the recovery really happened. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(recovery_id, bool)
                or not isinstance(recovery_id, str)
                or recovery_id not in self._recoveries
            ):
                raise UnknownRecoveryError(f"unknown recovery id: {recovery_id!r}")
            rec = self._recoveries[recovery_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=recovery_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-recovery.verify")
            return VerificationReport(
                record_id=recovery_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, incident_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one incident's recovery posture as data.

        Posture by ledger rule: ``unaddressed`` (nothing booked) ->
        ``unrecoverable`` (any failed) -> ``contested`` (any inconclusive)
        -> ``partially-recovered`` (any partial) -> ``recovered`` (all
        recovered). ``integrity_ok`` re-derives all in-scope digest pins
        as data. Seq is shape-validated only - never consumed, no audit
        row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            incident_id = _check_id(incident_id, "incident_id")
            if incident_id not in self._incident_recoveries:
                raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
            ids = self._incident_recoveries[incident_id]
            recs = [self._recoveries[i] for i in ids]
            n_recovered = sum(1 for r in recs if r.outcome == "recovered")
            n_partial = sum(1 for r in recs if r.outcome == "partial")
            n_failed = sum(1 for r in recs if r.outcome == "failed")
            n_inconclusive = sum(1 for r in recs if r.outcome == "inconclusive")
            if n_failed:
                posture = "unrecoverable"
            elif n_inconclusive:
                posture = "contested"
            elif n_partial:
                posture = "partially-recovered"
            elif n_recovered and n_recovered == len(recs):
                posture = "recovered"
            else:
                posture = "unaddressed"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                incident_id=incident_id,
                seq=seq,
                posture=posture,
                n_recoveries=len(recs),
                n_recovered=n_recovered,
                n_partial=n_partial,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-recovery.evaluate")
            return EvaluationReport(
                incident_id=incident_id,
                seq=seq,
                posture=posture,
                n_recoveries=len(recs),
                n_recovered=n_recovered,
                n_partial=n_partial,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def recovery_record(self, recovery_id: str, seq: int) -> RecoveryRecord:
        with self._lock:
            self._check_read_seq(seq)
            if recovery_id not in self._recoveries:
                raise UnknownRecoveryError(f"unknown recovery id: {recovery_id!r}")
            return self._recoveries[recovery_id]

    def retire_record(self, incident_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if incident_id not in self._retired:
                raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
            return self._retired[incident_id]

    def recoveries_for(self, incident_id: str, seq: int) -> Tuple[RecoveryRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._recoveries[i] for i in self._incident_recoveries.get(incident_id, [])
            )

    def incident_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._incident_recoveries))

    def recovery_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._recoveries))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_incidents": len(self._incident_recoveries),
                "n_recoveries": len(self._recoveries),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_RECOVERY_VERSION,
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
    """Self-check: exercise recover -> verify -> evaluate."""
    ledger = AIRecovery()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.recover(
        "incident-1",
        1,
        recovery_kind="capability-restoration",
        outcome="recovered",
    )
    assert rec.verify()
    rep = ledger.verify(rec.recovery_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("incident-1", 3)
    assert ev.posture == "recovered"
    ret = ledger.retire("incident-1", 4)
    assert ret.verify()
    print("ai-recovery OK: recover, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
