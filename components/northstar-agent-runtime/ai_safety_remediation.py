"""AI safety remediation: safety-hazard remediation decision ledger, Simulated.

Research note: Safety remediation is the field concerned with correcting
declared AI safety hazards once identified - the declared safety actions
taken (hazard mitigations, safety interlocks, output filters, capability
revocations, deployment holds, model rollbacks, safety retraining) and
the declared outcomes of those actions. This module is the *decision
ledger* for declared AI safety remediation: which safety-hazard ids had
which safety remediations booked (over a pinned safety-remediation-kind
vocabulary), what outcomes were declared against them (booked *as data*),
and what remediation posture the ledger derives - defensible
bookkeeping, never proof that a hazard is really gone.

This module owns the remediate -> verify -> evaluate lifecycle:

* **remediate()** - book one declared safety remediation against a
  declared safety-hazard id (minted ``srf-N`` ids; pinned
  safety-remediation-kind vocabulary over the common safety action
  classes; pinned outcome vocabulary booked *as data*); the first
  remediation registers its hazard; hazard logs, safety cases, fault
  trees, and raw material never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one remediation record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the remediation really ran.
* **evaluate()** - **pure read**: derive one hazard's remediation
  posture as data (``unevaluated`` -> ``failed`` -> ``contested`` ->
  ``partially-remediated`` -> ``remediated``) with outcome tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a hazard id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_remediation.py`` owns the
general remediation-*provision* lifecycle (declared remediation actions
against declared targets over a general action vocabulary);
``ai_safety.py`` owns the safety *assessment* -> *mitigation* lifecycle
(declared assessments against hazard kinds, declared mitigations against
assessments); ``ai_incident.py`` owns the incident report -> investigate
lifecycle; ``ai_recovery.py`` owns the incident-*recovery* lifecycle
(restoring a system from an incident) - this module is the
safety-*hazard remediation* ledger none of them own: declared safety
remediations against declared safety-hazard ids over a
safety-specific action vocabulary, declared outcomes, digest
re-derivation, and the ledger-rule posture that turns declared outcomes
into a remediation claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-safety-remediation.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no systems, applies
no remediations, and proves nothing about real AI safety remediation. A
booked ``remediated`` outcome means "the host declared it", never "the
hazard is gone"; a booked ``failed`` outcome means "the host declared
it", never "the remediation really failed". Hazard logs, safety cases,
fault trees, red-team traces, and raw remediation material never enter
records or cross the audit boundary - digest pins only.
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
AI_SAFETY_REMEDIATION_VERSION = "ai-safety-remediation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-safety-remediation.v1"

#: Pinned safety-remediation-kind vocabulary (the safety action classes booked).
SAFETY_REMEDIATION_KINDS = (
    "hazard-mitigation",
    "safety-interlock",
    "output-filter",
    "capability-revocation",
    "deployment-hold",
    "model-rollback",
    "safety-retraining",
    "no-action",
)

#: Pinned remediation-outcome vocabulary (booked as data, never proof).
REMEDIATION_OUTCOMES = (
    "remediated",
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
    "unevaluated",
    "contested",
    "partially-remediated",
    "failed",
    "remediated",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "remediated",
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
        "script",
        "scripts",
        "runbook",
        "runbooks",
        "playbook",
        "playbooks",
        "patch_file",
        "patch_diff",
        "rollback_plan",
        "hazard_log",
        "safety_case",
        "risk_assessment",
        "fault_tree",
        "harm_narrative",
        "red_team_trace",
        "eval_results",
        "fmea_record",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AISafetyRemediationError(Exception):
    """Base class for all ai-safety-remediation ledger errors."""


class BadHazardError(AISafetyRemediationError):
    pass


class UnknownHazardError(AISafetyRemediationError):
    pass


class RetiredHazardError(AISafetyRemediationError):
    pass


class BadKindError(AISafetyRemediationError):
    pass


class BadOutcomeError(AISafetyRemediationError):
    pass


class BadDigestError(AISafetyRemediationError):
    pass


class BadReasonError(AISafetyRemediationError):
    pass


class UnknownRemediationError(AISafetyRemediationError):
    pass


class UnknownRecordError(AISafetyRemediationError):
    pass


class SeqOrderError(AISafetyRemediationError):
    pass


class AuditKindError(AISafetyRemediationError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadHazardError(f"{what} must be a non-empty string")
    return value


def _check_kind(value: Any) -> str:
    if value not in SAFETY_REMEDIATION_KINDS:
        raise BadKindError(
            f"safety_remediation_kind must be one of {SAFETY_REMEDIATION_KINDS}"
        )
    return value


def _check_outcome(value: Any) -> str:
    if value not in REMEDIATION_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {REMEDIATION_OUTCOMES}")
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


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    if seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SafetyRemediationRecord:
    remediation_id: str
    hazard_id: str
    seq: int
    safety_remediation_kind: str
    outcome: str
    safety_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _remediate_payload(self), "ai-safety-remediation.remediate"
        )


@dataclass(frozen=True)
class RetireRecord:
    hazard_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-safety-remediation.retire"
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
            _verify_payload(self), "ai-safety-remediation.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    hazard_id: str
    seq: int
    posture: str
    n_remediations: int
    n_remediated: int
    n_partial: int
    n_failed: int
    n_inconclusive: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-safety-remediation.evaluate"
        )


def _remediate_payload(rec: "SafetyRemediationRecord") -> Dict[str, Any]:
    return {
        "remediation_id": rec.remediation_id,
        "hazard_id": rec.hazard_id,
        "seq": rec.seq,
        "safety_remediation_kind": rec.safety_remediation_kind,
        "outcome": rec.outcome,
        "safety_digest": rec.safety_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"hazard_id": rec.hazard_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "hazard_id": rep.hazard_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_remediations": rep.n_remediations,
        "n_remediated": rep.n_remediated,
        "n_partial": rep.n_partial,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "integrity_ok": rep.integrity_ok,
    }


def ai_safety_remediation_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AISafetyRemediationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-safety-remediation",
        "version": AI_SAFETY_REMEDIATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AISafetyRemediation:
    """AI-safety-remediation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All safety remediations and
    outcomes are booked as data - never proof that a hazard is really
    gone.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._remediations: Dict[str, SafetyRemediationRecord] = {}
        self._hazard_remediations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._remediation_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
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
            row = ai_safety_remediation_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-safety-remediation",
                "version": AI_SAFETY_REMEDIATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_safety_remediation_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, hazard_id: str) -> None:
        if hazard_id in self._retired:
            raise RetiredHazardError(f"hazard is retired: {hazard_id!r}")

    # -- mutations ---------------------------------------------------------

    def remediate(
        self,
        hazard_id: str,
        seq: int,
        safety_remediation_kind: str = "no-action",
        outcome: str = "inconclusive",
        safety_digest: str = "",
    ) -> SafetyRemediationRecord:
        """Book one declared safety remediation (minted ``srf-N`` id).

        The first remediation on an id registers the hazard. Hazard
        logs, safety cases, fault trees, and raw material never enter
        records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an
        ``ai-safety-remediation.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                hazard_id = _check_id(hazard_id, "hazard_id")
                self._require_seq(seq)
                safety_remediation_kind = _check_kind(safety_remediation_kind)
                outcome = _check_outcome(outcome)
                safety_digest = _check_digest(safety_digest, "safety_digest")
                self._require_live(hazard_id)
            except AISafetyRemediationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._remediation_counter += 1
            remediation_id = f"srf-{self._remediation_counter}"
            provisional = SafetyRemediationRecord(
                remediation_id=remediation_id,
                hazard_id=hazard_id,
                seq=seq,
                safety_remediation_kind=safety_remediation_kind,
                outcome=outcome,
                safety_digest=safety_digest,
                digest="",
            )
            digest = _digest_pin(
                _remediate_payload(provisional), "ai-safety-remediation.remediate"
            )
            rec = SafetyRemediationRecord(
                remediation_id=remediation_id,
                hazard_id=hazard_id,
                seq=seq,
                safety_remediation_kind=safety_remediation_kind,
                outcome=outcome,
                safety_digest=safety_digest,
                digest=digest,
            )
            self._remediations[remediation_id] = rec
            self._hazard_remediations.setdefault(hazard_id, []).append(remediation_id)
            self._emit(
                "remediated",
                seq,
                remediation_id=remediation_id,
                hazard_id=hazard_id,
                safety_remediation_kind=safety_remediation_kind,
                outcome=outcome,
            )
            return rec

    def retire(
        self, hazard_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a hazard id; ids are never recycled."""
        with self._lock:
            try:
                hazard_id = _check_id(hazard_id, "hazard_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if hazard_id not in self._hazard_remediations:
                    raise UnknownHazardError(f"unknown hazard: {hazard_id!r}")
                if hazard_id in self._retired:
                    raise RetiredHazardError(
                        f"hazard already retired: {hazard_id!r}"
                    )
            except AISafetyRemediationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                hazard_id=hazard_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-safety-remediation.retire"
            )
            rec = RetireRecord(
                hazard_id=hazard_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[hazard_id] = rec
            self._emit("retired", seq, hazard_id=hazard_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        return seq

    def _integrity_ok(self, hazard_id: str) -> bool:
        return all(
            self._remediations[rid].verify()
            for rid in self._hazard_remediations.get(hazard_id, [])
        )

    def _posture(self, hazard_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "remediated": 0,
            "partial": 0,
            "failed": 0,
            "inconclusive": 0,
        }
        ids = self._hazard_remediations.get(hazard_id, [])
        for rid in ids:
            tallies[self._remediations[rid].outcome] += 1
        if not ids:
            return "unevaluated", tallies
        if tallies["failed"]:
            return "failed", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["partial"]:
            return "partially-remediated", tallies
        return "remediated", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._remediations.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-safety-remediation.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, hazard_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one hazard's safety-remediation posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            hazard_id = _check_id(hazard_id, "hazard_id")
            if hazard_id not in self._hazard_remediations:
                raise UnknownHazardError(f"unknown hazard: {hazard_id!r}")
            posture, tallies = self._posture(hazard_id)
            provisional = EvaluationReport(
                hazard_id=hazard_id,
                seq=seq,
                posture=posture,
                n_remediations=len(self._hazard_remediations[hazard_id]),
                n_remediated=tallies["remediated"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                integrity_ok=self._integrity_ok(hazard_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-safety-remediation.evaluate"
            )
            return EvaluationReport(
                hazard_id=hazard_id,
                seq=seq,
                posture=posture,
                n_remediations=len(self._hazard_remediations[hazard_id]),
                n_remediated=tallies["remediated"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                integrity_ok=self._integrity_ok(hazard_id),
                digest=digest,
            )

    # -- views (pure reads) ------------------------------------------------

    def remediation_record(self, remediation_id: str, seq: int) -> SafetyRemediationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._remediations.get(remediation_id)
            if rec is None:
                raise UnknownRemediationError(
                    f"unknown remediation: {remediation_id!r}"
                )
            return rec

    def remediations_for(
        self, hazard_id: str, seq: int
    ) -> Tuple[SafetyRemediationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._remediations[rid]
                for rid in self._hazard_remediations.get(hazard_id, [])
            )

    def hazard_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._hazard_remediations.keys()))

    def remediation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._remediations.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_hazards": len(self._hazard_remediations),
                "n_remediations": len(self._remediations),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# stdlib self-check and CLI
# ---------------------------------------------------------------------------


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
    """Self-check: exercise remediate -> verify -> evaluate -> retire."""
    ledger = AISafetyRemediation()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.remediate(
        "hazard-1", 1, safety_remediation_kind="hazard-mitigation", outcome="failed"
    )
    assert rec.verify()
    rec2 = ledger.remediate(
        "hazard-1", 2, safety_remediation_kind="safety-interlock", outcome="remediated"
    )
    assert rec2.verify()
    rep = ledger.verify(rec.remediation_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("hazard-1", 4)
    assert ev.posture == "failed"
    ret = ledger.retire("hazard-1", 5)
    assert ret.verify()
    print("ai-safety-remediation OK: remediate, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
