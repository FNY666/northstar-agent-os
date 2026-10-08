"""AI robustness validation: robustness-validation decision ledger, Simulated.

Research note: robustness validation asks whether a declared
robustness posture actually holds - whether the robustness claims a
host makes (adversarial resilience proven, stress behavior mapped,
chaos drills passed, fault injection survived, distribution-shift
tolerance measured, load ceilings characterized, failover paths
exercised, and recovery procedures validated) have been put through
a declared robustness-validation engagement, and what verdict was
booked. It is the bookkeeping twin of robustness *declaration*
(which books the robustness assertions themselves): a host may
declare that its agent tolerates adversarial inputs under bounded
perturbation, but this module books the *validation engagements
themselves* - who ran what robustness validation, over which pinned
robustness-validation kind, with what declared verdict, pinned to
which digest. Defensible bookkeeping, never proof that the system is
really robust.

This module owns the validate -> verify -> evaluate lifecycle:

* **validate()** - book one declared robustness-validation
  engagement (minted ``rvl-N`` ids; pinned robustness-validation-
  kind vocabulary over the common AI-robustness validation
  classes; pinned verdict vocabulary booked *as data*); the first
  validation registers its system; raw adversarial corpora,
  stress harnesses, chaos manifests, fault-injection logs,
  and raw validation material never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one validation record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the robustness validation really happened.
* **evaluate()** - **pure read**: derive one system's robustness-
  validation posture as data (``unvalidated`` -> ``ineffective`` ->
  ``inconclusive`` -> ``partially-effective`` -> ``effective``)
  with verdict tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_robustness.py`` owns the
robustness-claim ledger (whether robustness is asserted);
``ai_robustness_testing.py`` owns the robustness-test-execution
ledger (whether robustness tests were run and what outcomes were
declared); ``ai_validation.py`` owns the generic fitness-for-purpose
validation lifecycle (did we build the right system) - this module
is the *robustness-validation engagement* ledger none of them own:
declared robustness-validation engagements over a pinned
robustness-validation-kind vocabulary, declared robustness verdicts,
digest re-derivation, and the ledger-rule posture that turns declared
verdicts into a robustness-validation claim, always as data, never as
measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-robustness-validation.rejected`` row; rewinds raise bare
without consuming), no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json`` try/except
fallback, ``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module validates nothing, runs no robustness
tests, probes no adversarial inputs, collects no evidence, and
proves nothing about real robustness. A booked ``effective``
verdict means "the host declared it", never "the system is
robust"; a booked ``ineffective`` verdict means "the host declared
it", never "the system is fragile". Adversarial corpora, stress
harnesses, chaos manifests, fault-injection logs, and raw validation
material never enter records or cross the audit boundary - digest
pins only.
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
AI_ROBUSTNESS_VALIDATION_VERSION = "ai-robustness-validation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-robustness-validation.v1"

#: Pinned robustness-validation-kind vocabulary (the AI-robustness validation classes).
VALIDATION_KINDS = (
    "adversarial-validation",
    "stress-validation",
    "chaos-validation",
    "fault-injection-validation",
    "distribution-shift-validation",
    "load-validation",
    "failover-validation",
    "recovery-validation",
)

#: Pinned robustness-verdict vocabulary (booked as data, never proof).
VALIDATION_VERDICTS = (
    "effective",
    "partially-effective",
    "ineffective",
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
    "ineffective",
    "inconclusive",
    "partially-effective",
    "effective",
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
    "validated",
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
        "evidence",
        "evidence_pack",
        "evidence_packs",
        "protocol",
        "protocols",
        "test_protocol",
        "test_protocols",
        "benchmark",
        "benchmarks",
        "dataset",
        "datasets",
        "report",
        "reports",
        "validations",
        "validation_reports",
        "validation_evidence",
        "workpapers",
        "questionnaire",
        "checklist",
        "adversarial_corpus",
        "adversarial_corpora",
        "adversarial_examples",
        "adversarial_prompts",
        "perturbation_set",
        "attack_suite",
        "attack_traces",
        "red_team_log",
        "red_team_logs",
        "stress_harness",
        "stress_results",
        "load_profile",
        "load_profiles",
        "load_test_results",
        "chaos_manifest",
        "chaos_experiment",
        "chaos_results",
        "fault_injection_log",
        "fault_injection_plan",
        "fault_manifest",
        "distribution_shift_suite",
        "shift_scenarios",
        "ood_corpus",
        "failover_plan",
        "failover_log",
        "failover_results",
        "recovery_procedure",
        "recovery_log",
        "recovery_results",
        "disaster_recovery_plan",
        "resilience_scorecard",
        "robustness_scorecard",
        "degradation_curve",
        "latency_distribution",
        "error_budget",
        "slo_report",
        "incident_replay",
        "postmortem",
    }
)

# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIRobustnessValidationError(Exception):
    """Base class for all ai-robustness-validation ledger errors."""


class BadSystemError(AIRobustnessValidationError):
    pass


class UnknownSystemError(AIRobustnessValidationError):
    pass


class RetiredSystemError(AIRobustnessValidationError):
    pass


class BadValidationKindError(AIRobustnessValidationError):
    pass


class BadVerdictError(AIRobustnessValidationError):
    pass


class BadDigestError(AIRobustnessValidationError):
    pass


class BadReasonError(AIRobustnessValidationError):
    pass


class UnknownValidationError(AIRobustnessValidationError):
    pass


class UnknownRecordError(AIRobustnessValidationError):
    pass


class SeqOrderError(AIRobustnessValidationError):
    pass


class AuditKindError(AIRobustnessValidationError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_validation_kind(value: Any) -> str:
    if value not in VALIDATION_KINDS:
        raise BadValidationKindError(
            f"validation_kind must be one of {VALIDATION_KINDS}"
        )
    return value


def _check_verdict(value: Any) -> str:
    if value not in VALIDATION_VERDICTS:
        raise BadVerdictError(
            f"verdict must be one of {VALIDATION_VERDICTS}"
        )
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
    return seq


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
            _validation_payload(self), "ai-robustness-validation.validate"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-robustness-validation.retire"
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
            _verify_payload(self), "ai-robustness-validation.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_validations: int
    n_effective: int
    n_partially_effective: int
    n_ineffective: int
    n_inconclusive: int
    n_not_validated: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-robustness-validation.evaluate"
        )


def _validation_payload(rec: "ValidationRecord") -> Dict[str, Any]:
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
        "n_effective": rep.n_effective,
        "n_partially_effective": rep.n_partially_effective,
        "n_ineffective": rep.n_ineffective,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_validated": rep.n_not_validated,
        "integrity_ok": rep.integrity_ok,
    }


def ai_robustness_validation_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIRobustnessValidationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-robustness-validation",
        "version": AI_ROBUSTNESS_VALIDATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIRobustnessValidation:
    """AI-robustness-validation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All robustness
    validations, verdicts, and postures are booked as data - never proof
    that a robustness validation really happened or that robustness is
    really effective.
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

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_robustness_validation_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-robustness-validation",
                "version": AI_ROBUSTNESS_VALIDATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_robustness_validation_audit_event(kind, seq, **details)
        )

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def validate(
        self,
        system_id: str,
        seq: int,
        validation_kind: str = "adversarial-validation",
        verdict: str = "not-validated",
        validation_digest: str = "",
    ) -> ValidationRecord:
        """Book one declared robustness-validation engagement (minted ``rvl-N`` id).

        The first validation on an id registers the system. Raw
        adversarial corpora, stress harnesses, chaos manifests,
        fault-injection logs, and raw validation material never enter
        records - digest pins only. Fail-closed: failed
        mutations consume their seq and book an
        ``ai-robustness-validation.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                validation_kind = _check_validation_kind(validation_kind)
                verdict = _check_verdict(verdict)
                validation_digest = _check_digest(validation_digest, "validation_digest")
                self._require_live(system_id)
            except AIRobustnessValidationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._validation_counter += 1
            validation_id = f"rvl-{self._validation_counter}"
            provisional = ValidationRecord(
                validation_id=validation_id,
                system_id=system_id,
                seq=seq,
                validation_kind=validation_kind,
                verdict=verdict,
                validation_digest=validation_digest,
                digest="",
            )
            digest = _digest_pin(
                _validation_payload(provisional),
                "ai-robustness-validation.validate",
            )
            rec = ValidationRecord(
                validation_id=validation_id,
                system_id=system_id,
                seq=seq,
                validation_kind=validation_kind,
                verdict=verdict,
                validation_digest=validation_digest,
                digest=digest,
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

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_validations:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIRobustnessValidationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-robustness-validation.retire"
            )
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._validations[vid].verify()
            for vid in self._system_validations.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "effective": 0,
            "partially-effective": 0,
            "ineffective": 0,
            "inconclusive": 0,
            "not-validated": 0,
        }
        ids = self._system_validations.get(system_id, [])
        for vid in ids:
            tallies[self._validations[vid].verdict] += 1
        if not ids:
            return "unvalidated", tallies
        if tallies["ineffective"]:
            return "ineffective", tallies
        if tallies["inconclusive"]:
            return "inconclusive", tallies
        if tallies["partially-effective"]:
            return "partially-effective", tallies
        if all(self._validations[vid].verdict == "effective" for vid in ids):
            return "effective", tallies
        return "partially-effective", tallies

    def verify(self, validation_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one validation record's digest pin."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._validations.get(validation_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {validation_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=validation_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-robustness-validation.verify"
            )
            return VerificationReport(
                record_id=validation_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's robustness-validation posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_validations:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_validations=len(self._system_validations[system_id]),
                n_effective=tallies["effective"],
                n_partially_effective=tallies["partially-effective"],
                n_ineffective=tallies["ineffective"],
                n_inconclusive=tallies["inconclusive"],
                n_not_validated=tallies["not-validated"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional),
                "ai-robustness-validation.evaluate",
            )
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_validations=len(self._system_validations[system_id]),
                n_effective=tallies["effective"],
                n_partially_effective=tallies["partially-effective"],
                n_ineffective=tallies["ineffective"],
                n_inconclusive=tallies["inconclusive"],
                n_not_validated=tallies["not-validated"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) ------------------------------------------------

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
            return tuple(
                self._validations[vid]
                for vid in self._system_validations.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_validations.keys()))

    def validation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._validations.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_validations),
                "n_validations": len(self._validations),
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
    """Self-check: exercise validate -> verify -> evaluate."""
    ledger = AIRobustnessValidation()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.validate(
        "sys-1",
        1,
        validation_kind="adversarial-validation",
        verdict="partially-effective",
    )
    assert rec.verify()
    rep = ledger.verify(rec.validation_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 3)
    assert ev.posture == "partially-effective"
    ret = ledger.retire("sys-1", 4)
    assert ret.verify()
    print(
        "ai-robustness-validation OK: validate, verify, evaluate, retire, pins, audit"
    )


if __name__ == "__main__":
    main()
