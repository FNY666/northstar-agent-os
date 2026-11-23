"""AI safety validation: safety-validation decision ledger, Simulated.

Research note: Safety validation is the practice of checking, before and
after deployment, that an AI system satisfies its declared safety
requirements - validating behavior against safety properties, validating
that declared mitigations were applied, and validating that residual risk
claims hold. This module is the *decision ledger* for declared AI-safety
validations: which systems had which safety validations booked (over a
pinned validation-kind vocabulary), what verdicts were declared against
them, and what validation posture the ledger derives - defensible
bookkeeping, never proof that a system is really safe.

This module owns the validate -> verify -> evaluate lifecycle:

* **validate()** - book one declared safety validation (minted ``val-N``
  ids; pinned validation-kind vocabulary over the common safety-validation
  gates; pinned verdict vocabulary booked *as data*); the first validation
  registers its system; raw validation reports, test transcripts, and
  material never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one validation record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as proof
  the validation really happened.
* **evaluate()** - **pure read**: derive one system's validation posture as
  data (``unvalidated`` -> ``unsafe`` -> ``contested`` ->
  ``conditionally-safe`` -> ``validated``) with verdict tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_safety.py`` owns the
assessment->mitigation lifecycle (declared hazard assessments, minted
``asm-N``, and declared mitigation chains); ``ai_validation.py`` owns
general fitness-for-purpose V&V (verification against spec, validation
against intent); ``safety_case.py`` owns the safety-case *argument
structure* (claims/arguments/evidence bookkeeping); ``safety_eval.py``
owns the evaluation-run lifecycle; ``ai_certification.py`` owns
third-party attestation records - this module is the safety-*validation
gate* decision ledger none of them own: declared safety-validation runs
over a pinned gate vocabulary, declared gate verdicts, digest
re-derivation, and the ledger-rule posture that turns declared verdicts
into a validation claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-safety-validation.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no systems, validates
nothing in reality, and proves nothing about real AI safety. A booked
``safe-to-deploy`` verdict means "the host declared it", never "the system
is safe"; a booked ``unsafe`` verdict means "the host declared it", never
"the system is unsafe". Validation reports, test transcripts, behavior
traces, weights, prompts, and raw validation material never enter records
or cross the audit boundary - digest pins only.
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
AI_SAFETY_VALIDATION_VERSION = "ai-safety-validation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-safety-validation.v1"

#: Pinned validation-kind vocabulary (the safety-validation gates booked).
VALIDATION_KINDS = (
    "pre-deployment-validation",
    "post-deployment-validation",
    "regression-validation",
    "red-team-validation",
    "formal-check-validation",
    "behavioral-audit-validation",
    "scenario-validation",
    "incident-driven-validation",
)

#: Pinned validation-verdict vocabulary (booked as data, never proof).
VALIDATION_VERDICTS = (
    "safe-to-deploy",
    "safe-with-conditions",
    "unsafe",
    "inconclusive",
    "not-validated",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unvalidated",
    "unsafe",
    "contested",
    "conditionally-safe",
    "validated",
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
    "validated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "validation_report",
        "validation_transcript",
        "test_transcript",
        "behavior_trace",
        "weights",
        "prompt",
        "completion",
        "test_case",
        "test_suite",
        "eval_result",
        "scenario",
        "scenario_script",
        "red_team_transcript",
        "attack_trace",
        "evidence",
        "artifact",
        "artifact_bytes",
        "model_output",
        "model_response",
        "log",
        "logs",
        "telemetry",
        "trace",
        "recording",
        "screenshot",
        "video",
        "audio",
        "image",
        "dataset",
        "training_data",
        "fine_tune_data",
        "system_prompt",
        "config",
        "configuration",
        "policy_text",
        "safety_policy",
        "safety_case",
        "safety_argument",
        "hazard_analysis",
        "risk_register",
        "threat_model",
        "review_notes",
        "auditor_notes",
        "attestation_text",
        "certificate",
        "finding",
        "findings",
        "observation",
        "remediation_plan",
        "action_plan",
        "workpaper",
        "checklist",
        "questionnaire",
        "interview_notes",
        "sign_off",
        "approval",
        "credentials",
        "api_key",
        "secret",
        "token",
        "password",
        "private_key",
        "pii",
        "personal_data",
        "user_data",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class AISafetyValidationError(Exception):
    """Base error for the safety-validation decision ledger."""


class BadSystemIdError(AISafetyValidationError):
    pass


class BadValidationKindError(AISafetyValidationError):
    pass


class BadVerdictError(AISafetyValidationError):
    pass


class BadDigestError(AISafetyValidationError):
    pass


class BadReasonError(AISafetyValidationError):
    pass


class RetiredSystemError(AISafetyValidationError):
    pass


class UnknownSystemError(AISafetyValidationError):
    pass


class UnknownValidationError(AISafetyValidationError):
    pass


class SeqOrderError(AISafetyValidationError):
    pass


class AuditKindError(AISafetyValidationError):
    pass


# ---------------------------------------------------------------------------
# Canonical JSON + digest pins
# ---------------------------------------------------------------------------


def _canonical_bytes(obj: Any) -> bytes:
    out = _jcs_dumps(obj)
    if isinstance(out, str):
        out = out.encode("utf-8")
    return out


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


def _check_digest(digest: Any) -> str:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise BadDigestError("digest must be a sha256: pin")
    return digest


def _check_system_id(system_id: Any) -> str:
    if not isinstance(system_id, str) or not system_id or len(system_id) > 256:
        raise BadSystemIdError("system_id must be a non-empty string")
    return system_id


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationRecord:
    validation_id: str
    system_id: str
    seq: int
    validation_kind: str
    verdict: str
    validation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _validate_payload(self), "ai-safety-validation.validate"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-safety-validation.retire"
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
            _verify_payload(self), "ai-safety-validation.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_validations: int
    n_safe_to_deploy: int
    n_safe_with_conditions: int
    n_unsafe: int
    n_inconclusive: int
    n_not_validated: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-safety-validation.evaluate"
        )


def _validate_payload(rec: "ValidationRecord") -> Dict[str, Any]:
    return {
        "validation_id": rec.validation_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "validation_kind": rec.validation_kind,
        "verdict": rec.verdict,
        "validation_digest": rec.validation_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_validations": rep.n_validations,
        "n_safe_to_deploy": rep.n_safe_to_deploy,
        "n_safe_with_conditions": rep.n_safe_with_conditions,
        "n_unsafe": rep.n_unsafe,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_validated": rep.n_not_validated,
        "integrity_ok": rep.integrity_ok,
    }


def ai_safety_validation_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AISafetyValidationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-safety-validation",
        "version": AI_SAFETY_VALIDATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AISafetyValidation:
    """AI-safety validation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All validations are booked as
    data - never proof that a system is really safe.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._validations: Dict[str, ValidationRecord] = {}
        self._system_validations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._validation_counter = 0
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

    def _require_read_seq(self, seq: int) -> int:
        return _check_seq(seq)

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_safety_validation_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-safety-validation",
                "version": AI_SAFETY_VALIDATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_safety_validation_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def validate(
        self,
        system_id: str,
        seq: int,
        validation_kind: str = "pre-deployment-validation",
        verdict: str = "not-validated",
        validation_digest: str = "",
    ) -> ValidationRecord:
        """Book one declared safety validation (minted ``val-N`` ids).

        The first validation for a system registers that system. Raw
        validation material never enters the record - digest pins only.
        Fail-closed: bad input burns the seq and books a
        ``ai-safety-validation.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_system_id(system_id)
                self._claim(seq)
                if validation_kind not in VALIDATION_KINDS:
                    raise BadValidationKindError(
                        f"unknown validation kind: {validation_kind!r}"
                    )
                if verdict not in VALIDATION_VERDICTS:
                    raise BadVerdictError(f"unknown verdict: {verdict!r}")
                if validation_digest != "":
                    _check_digest(validation_digest)
                self._require_live(system_id)
            except AISafetyValidationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._validation_counter += 1
            validation_id = f"val-{self._validation_counter}"
            rec = ValidationRecord(
                validation_id=validation_id,
                system_id=system_id,
                seq=seq,
                validation_kind=validation_kind,
                verdict=verdict,
                validation_digest=validation_digest,
                digest=_digest_pin(
                    {
                        "validation_id": validation_id,
                        "system_id": system_id,
                        "seq": seq,
                        "validation_kind": validation_kind,
                        "verdict": verdict,
                        "validation_digest": validation_digest,
                    },
                    "ai-safety-validation.validate",
                ),
            )
            self._validations[validation_id] = rec
            self._system_validations.setdefault(system_id, []).append(validation_id)
            self._emit(
                "validated",
                seq,
                validation_id=validation_id,
                system_id=system_id,
                validation_kind=validation_kind,
                verdict=verdict,
            )
            return rec

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_system_id(system_id)
                self._claim(seq)
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"unknown reason: {reason!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
                if system_id not in self._system_validations:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
            except AISafetyValidationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            rec = RetireRecord(
                system_id=system_id,
                seq=seq,
                reason=reason,
                digest=_digest_pin(
                    {"system_id": system_id, "seq": seq, "reason": reason},
                    "ai-safety-validation.retire",
                ),
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def verify(self, validation_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one validation record's digest pin.

        Verdict ``verified`` / ``tampered`` is booked as data (tamper is
        reported, never raised). Seq is shape-validated only - never
        consumed, no audit row.
        """
        with self._lock:
            self._require_read_seq(seq)
            rec = self._validations.get(validation_id)
            if rec is None:
                raise UnknownValidationError(
                    f"unknown validation: {validation_id!r}"
                )
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            rep = VerificationReport(
                record_id=validation_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "record_id": validation_id,
                        "seq": seq,
                        "verdict": verdict,
                        "integrity_ok": integrity_ok,
                    },
                    "ai-safety-validation.verify",
                ),
            )
            return rep

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's validation posture as data.

        Posture ladder: ``unvalidated`` (no validations) -> ``unsafe``
        (any ``unsafe`` verdict, outranks) -> ``contested`` (any
        ``inconclusive``) -> ``conditionally-safe`` (any
        ``safe-with-conditions`` or ``not-validated``) -> ``validated``
        (all ``safe-to-deploy``).
        """
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_system_id(system_id)
            ids = self._system_validations.get(system_id, ())
            verdicts = [self._validations[i].verdict for i in ids]
            n_unsafe = sum(v == "unsafe" for v in verdicts)
            n_inconclusive = sum(v == "inconclusive" for v in verdicts)
            n_safe_with_conditions = sum(v == "safe-with-conditions" for v in verdicts)
            n_not_validated = sum(v == "not-validated" for v in verdicts)
            n_safe_to_deploy = sum(v == "safe-to-deploy" for v in verdicts)
            if not verdicts:
                posture = "unvalidated"
            elif n_unsafe:
                posture = "unsafe"
            elif n_inconclusive:
                posture = "contested"
            elif n_safe_with_conditions or n_not_validated:
                posture = "conditionally-safe"
            else:
                posture = "validated"
            integrity_ok = all(self._validations[i].verify() for i in ids)
            rep = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_validations=len(ids),
                n_safe_to_deploy=n_safe_to_deploy,
                n_safe_with_conditions=n_safe_with_conditions,
                n_unsafe=n_unsafe,
                n_inconclusive=n_inconclusive,
                n_not_validated=n_not_validated,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "system_id": system_id,
                        "seq": seq,
                        "posture": posture,
                        "n_validations": len(ids),
                        "n_safe_to_deploy": n_safe_to_deploy,
                        "n_safe_with_conditions": n_safe_with_conditions,
                        "n_unsafe": n_unsafe,
                        "n_inconclusive": n_inconclusive,
                        "n_not_validated": n_not_validated,
                        "integrity_ok": integrity_ok,
                    },
                    "ai-safety-validation.evaluate",
                ),
            )
            return rep

    # -- pure-read views ---------------------------------------------------

    def validation_record(self, validation_id: str, seq: int) -> ValidationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._validations.get(validation_id)
            if rec is None:
                raise UnknownValidationError(
                    f"unknown validation: {validation_id!r}"
                )
            return rec

    def validations_for(self, system_id: str, seq: int) -> Tuple[ValidationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            _check_system_id(system_id)
            return tuple(
                self._validations[i]
                for i in self._system_validations.get(system_id, ())
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_validations))

    def validation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._validations))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "n_validations": len(self._validations),
                "n_systems": len(self._system_validations),
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
    """Self-check: exercise validate -> verify -> evaluate -> retire."""
    ledger = AISafetyValidation()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.validate(
        "sys-1",
        1,
        validation_kind="pre-deployment-validation",
        verdict="safe-to-deploy",
    )
    assert rec.validation_id == "val-1"
    assert rec.verify()
    rep = ledger.verify(rec.validation_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 3)
    assert ev.posture == "validated"
    ret = ledger.retire("sys-1", 4)
    assert ret.verify()
    print("ai-safety-validation OK: validate, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
