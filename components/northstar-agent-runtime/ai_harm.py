"""AI harm: harm assessment/mitigation decision ledger, Simulated.

Research note: AI harm is the field concerned with the harms AI systems
can cause or enable - physical, psychological, economic, social, and
environmental harms; rights violations; discriminatory impacts; and
informational harms. This module is the *decision ledger* for declared
AI-harm assessments: which systems had which harm assessments booked
(over a pinned harm-kind vocabulary), what verdicts were declared against
them, what mitigations the host declared, and what harm posture the
ledger derives - defensible bookkeeping, never proof that a system is
really harmless.

This module owns the assess -> mitigate -> evaluate lifecycle:

* **assess()** - book one declared harm assessment (minted ``asm-N``
  ids; pinned harm-kind vocabulary over the common AI-harm classes;
  pinned verdict vocabulary booked *as data*; host-reported severity
  booked *as data*); the first assessment registers its system; raw
  incident reports, harm narratives, victim identities, and material
  never enter records - digest pins only.
* **mitigate()** - book one declared mitigation against a booked
  assessment (minted ``mit-N`` ids; pinned mitigation-strategy
  vocabulary booked *as data*); repeatable chain; books the
  *declaration*, never the deployed fix.
* **verify()** - **pure read**: re-derive one assessment/mitigation
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the assessment really happened.
* **evaluate()** - **pure read**: derive one system's harm posture as
  data (``unassessed`` -> ``harm-open`` -> ``contested`` ->
  ``mitigated`` -> ``no-harm``) with verdict tallies and a digest-pinned
  integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_safety.py`` owns the
AI-safety assessment/mitigation lifecycle over hazard classes with
safe/unsafe verdicts; ``ai_harm.py`` is the *harm* ledger none of them
own - declared harm incidents and their verdicts over a pinned
harm-kind vocabulary, harm-specific severity, and harm-specific
mitigation strategies (remediation, compensation, apology, record
correction); ``ai_redress.py`` owns the remedy-provision lifecycle
(apologies/compensation/retractions); ``ai_liability.py`` owns the
legal-liability assessment lifecycle; ``ai_oversight.py`` owns oversight
sessions; ``ai_ethics.py`` owns ethics assessments - this module is the
AI-harm assessment/mitigation decision ledger: declared harm
assessments, declared mitigations, digest re-derivation, and the
ledger-rule posture that turns declared verdicts into a harm claim,
always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-harm.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no systems, applies
no mitigations, and proves nothing about real AI harm. A booked
``harm-detected`` verdict means "the host declared it", never "the
system caused harm"; a booked mitigation means "the host declared it",
never "the harm is gone". Incident reports, harm narratives, victim
identities, damage figures, and raw assessment material never enter
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
AI_HARM_VERSION = "ai-harm.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-harm.v1"

#: Pinned harm-kind vocabulary (the AI-harm classes assessed).
HARM_KINDS = (
    "physical-harm",
    "psychological-harm",
    "economic-harm",
    "social-harm",
    "environmental-harm",
    "rights-violation",
    "discrimination-harm",
    "informational-harm",
)

#: Pinned assessment-verdict vocabulary (booked as data, never proof).
ASSESS_VERDICTS = (
    "harm-detected",
    "suspected",
    "inconclusive",
    "no-harm",
    "not-assessed",
)

#: Pinned mitigation-strategy vocabulary (booked as data, never proof).
MITIGATION_STRATEGIES = (
    "remediation",
    "compensation",
    "containment",
    "prevention-hardening",
    "monitoring-escalation",
    "policy-change",
    "deployment-hold",
    "no-action",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unassessed",
    "harm-open",
    "contested",
    "mitigated",
    "no-harm",
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
    "assessed",
    "mitigated",
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
        "incident",
        "incidents",
        "incident_report",
        "harm_report",
        "harm_narrative",
        "victim",
        "victims",
        "victim_identity",
        "claimant",
        "damages",
        "damage_estimate",
        "lawsuit",
        "settlement",
        "payout",
        "compensation_amount",
        "bank_details",
        "personal_data",
        "complaint",
        "complaint_text",
        "remedy_text",
        "evidence",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIHarmError(Exception):
    """Base class for all ai-harm ledger errors."""


class BadSystemError(AIHarmError):
    pass


class UnknownSystemError(AIHarmError):
    pass


class RetiredSystemError(AIHarmError):
    pass


class BadHarmKindError(AIHarmError):
    pass


class BadVerdictError(AIHarmError):
    pass


class BadSeverityError(AIHarmError):
    pass


class BadDigestError(AIHarmError):
    pass


class BadReasonError(AIHarmError):
    pass


class UnknownAssessmentError(AIHarmError):
    pass


class UnknownMitigationError(AIHarmError):
    pass


class UnknownRecordError(AIHarmError):
    pass


class BadStrategyError(AIHarmError):
    pass


class SeqOrderError(AIHarmError):
    pass


class AuditKindError(AIHarmError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_harm_kind(value: Any) -> str:
    if value not in HARM_KINDS:
        raise BadHarmKindError(f"harm_kind must be one of {HARM_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in ASSESS_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {ASSESS_VERDICTS}")
    return value


def _check_strategy(value: Any) -> str:
    if value not in MITIGATION_STRATEGIES:
        raise BadStrategyError(f"strategy must be one of {MITIGATION_STRATEGIES}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int in [0, 100]")
    if value < 0 or value > 100:
        raise BadSeverityError("severity must be an int in [0, 100]")
    return value


def _check_digest(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"{what} must be a string")
    if value == "":
        return value
    if not value.startswith("sha256:"):
        raise BadDigestError(f"{what} must be '' or a 'sha256:' digest pin")
    hexpart = value[len("sha256:"):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or a 'sha256:' digest pin")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    if seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return seq


def _check_read_seq(seq: Any) -> int:
    """Shape-only check for pure-read seqs: never consumes, never burns."""
    return _check_seq(seq)


# ---------------------------------------------------------------------------
# Digest pins
# ---------------------------------------------------------------------------


def _canonical_bytes(obj: Any) -> bytes:
    out = _jcs_dumps(obj)
    if isinstance(out, str):
        return out.encode("utf-8")
    return out


def _digest_pin(payload: Dict[str, Any], tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "version": AI_HARM_VERSION, **payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    system_id: str
    seq: int
    harm_kind: str
    verdict: str
    severity: int
    assessment_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _assess_payload(self), "ai-harm.assess"
        )


@dataclass(frozen=True)
class MitigationRecord:
    mitigation_id: str
    assessment_id: str
    system_id: str
    seq: int
    strategy: str
    mitigation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _mitigate_payload(self), "ai-harm.mitigate"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-harm.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-harm.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_assessments: int
    n_harm_detected: int
    n_suspected: int
    n_inconclusive: int
    n_no_harm: int
    n_not_assessed: int
    n_mitigated: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-harm.evaluate"
        )


def _assess_payload(rec: "AssessmentRecord") -> Dict[str, Any]:
    return {
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "harm_kind": rec.harm_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "assessment_digest": rec.assessment_digest,
    }


def _mitigate_payload(rec: "MitigationRecord") -> Dict[str, Any]:
    return {
        "mitigation_id": rec.mitigation_id,
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "strategy": rec.strategy,
        "mitigation_digest": rec.mitigation_digest,
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
        "n_assessments": rep.n_assessments,
        "n_harm_detected": rep.n_harm_detected,
        "n_suspected": rep.n_suspected,
        "n_inconclusive": rep.n_inconclusive,
        "n_no_harm": rep.n_no_harm,
        "n_not_assessed": rep.n_not_assessed,
        "n_mitigated": rep.n_mitigated,
        "integrity_ok": rep.integrity_ok,
    }


def ai_harm_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIHarmError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-harm",
        "version": AI_HARM_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIHarm:
    """AI-harm assessment/mitigation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and mitigations
    are booked as data - never proof that a system really caused no harm.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._system_assessments: Dict[str, List[str]] = {}
        self._assessment_mitigations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assessment_counter = 0
        self._mitigation_counter = 0
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
            row = ai_harm_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-harm",
                "version": AI_HARM_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_harm_audit_event(kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        harm_kind: str = "physical-harm",
        verdict: str = "not-assessed",
        severity: int = 0,
        assessment_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared harm assessment (minted ``asm-N`` id).

        The first assessment on an id registers the system. Raw incident
        reports, harm narratives, victim identities, and material never
        enter records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an ``ai-harm.rejected`` row; rewinds
        raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                harm_kind = _check_harm_kind(harm_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                assessment_digest = _check_digest(
                    assessment_digest, "assessment_digest"
                )
                self._require_live(system_id)
            except AIHarmError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._assessment_counter += 1
            assessment_id = f"asm-{self._assessment_counter}"
            provisional = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                harm_kind=harm_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
                digest="",
            )
            digest = _digest_pin(_assess_payload(provisional), "ai-harm.assess")
            rec = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                harm_kind=harm_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
                digest=digest,
            )
            self._assessments[assessment_id] = rec
            self._system_assessments.setdefault(system_id, []).append(assessment_id)
            self._assessment_mitigations.setdefault(assessment_id, [])
            self._emit(
                "assessed",
                seq,
                assessment_id=assessment_id,
                system_id=system_id,
                harm_kind=harm_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
            )
            return rec

    def mitigate(
        self,
        assessment_id: str,
        seq: int,
        strategy: str = "no-action",
        mitigation_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation against a booked assessment.

        Minted ``mit-N`` ids; repeatable chain. Books the *declaration*,
        never the deployed fix. Fail-closed on unknown assessments and
        retired systems.
        """
        with self._lock:
            try:
                assessment_id = _check_id(assessment_id, "assessment_id")
                self._require_seq(seq)
                strategy = _check_strategy(strategy)
                mitigation_digest = _check_digest(
                    mitigation_digest, "mitigation_digest"
                )
                assessment = self._assessments.get(assessment_id)
                if assessment is None:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}"
                    )
                self._require_live(assessment.system_id)
            except AIHarmError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._mitigation_counter += 1
            mitigation_id = f"mit-{self._mitigation_counter}"
            system_id = assessment.system_id
            provisional = MitigationRecord(
                mitigation_id=mitigation_id,
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                strategy=strategy,
                mitigation_digest=mitigation_digest,
                digest="",
            )
            digest = _digest_pin(_mitigate_payload(provisional), "ai-harm.mitigate")
            rec = MitigationRecord(
                mitigation_id=mitigation_id,
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                strategy=strategy,
                mitigation_digest=mitigation_digest,
                digest=digest,
            )
            self._mitigations[mitigation_id] = rec
            self._assessment_mitigations[assessment_id].append(mitigation_id)
            self._emit(
                "mitigated",
                seq,
                mitigation_id=mitigation_id,
                assessment_id=assessment_id,
                system_id=system_id,
                strategy=strategy,
                mitigation_digest=mitigation_digest,
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
                if system_id not in self._system_assessments:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system is retired: {system_id!r}")
            except AIHarmError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-harm.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads ---------------------------------------------------------

    def _get_record(self, record_id: str) -> Tuple[str, Any]:
        if record_id in self._assessments:
            return ("assessment", self._assessments[record_id])
        if record_id in self._mitigations:
            return ("mitigation", self._mitigations[record_id])
        if record_id in self._retired:
            return ("retire", self._retired[record_id])
        raise UnknownRecordError(f"unknown record: {record_id!r}")

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the assessment really happened.
        """
        with self._lock:
            _check_read_seq(seq)
            record_id = _check_id(record_id, "record_id")
            kind, rec = self._get_record(record_id)
            ok = rec.verify()
            verdict = "verified" if ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-harm.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's harm posture as data.

        Posture rule (precedence): ``unassessed`` (unknown system raises;
        no assessments booked) -> ``harm-open`` (any unmitigated
        ``harm-detected``) -> ``contested`` (any ``suspected`` /
        ``inconclusive``) -> ``mitigated`` (all ``harm-detected``
        covered by at least one mitigation) -> ``no-harm`` (all
        ``no-harm``).
        """
        with self._lock:
            _check_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_assessments:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            assessment_ids = self._system_assessments[system_id]
            n_harm_detected = n_suspected = n_inconclusive = 0
            n_no_harm = n_not_assessed = n_mitigated = 0
            integrity_ok = True
            harm_open = False
            for aid in assessment_ids:
                rec = self._assessments[aid]
                if not rec.verify():
                    integrity_ok = False
                if rec.verdict == "harm-detected":
                    n_harm_detected += 1
                    if not self._assessment_mitigations[aid]:
                        harm_open = True
                    else:
                        n_mitigated += 1
                elif rec.verdict == "suspected":
                    n_suspected += 1
                elif rec.verdict == "inconclusive":
                    n_inconclusive += 1
                elif rec.verdict == "no-harm":
                    n_no_harm += 1
                else:
                    n_not_assessed += 1
            if not assessment_ids or n_not_assessed == len(assessment_ids):
                posture = "unassessed"
            elif harm_open:
                posture = "harm-open"
            elif n_suspected or n_inconclusive:
                posture = "contested"
            elif n_harm_detected and n_mitigated == n_harm_detected:
                posture = "mitigated"
            elif n_no_harm and n_harm_detected == 0:
                posture = "no-harm"
            else:
                posture = "contested"
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(assessment_ids),
                n_harm_detected=n_harm_detected,
                n_suspected=n_suspected,
                n_inconclusive=n_inconclusive,
                n_no_harm=n_no_harm,
                n_not_assessed=n_not_assessed,
                n_mitigated=n_mitigated,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-harm.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(assessment_ids),
                n_harm_detected=n_harm_detected,
                n_suspected=n_suspected,
                n_inconclusive=n_inconclusive,
                n_no_harm=n_no_harm,
                n_not_assessed=n_not_assessed,
                n_mitigated=n_mitigated,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views ----------------------------------------------------

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        with self._lock:
            _check_read_seq(seq)
            assessment_id = _check_id(assessment_id, "assessment_id")
            rec = self._assessments.get(assessment_id)
            if rec is None:
                raise UnknownAssessmentError(f"unknown assessment: {assessment_id!r}")
            return rec

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        with self._lock:
            _check_read_seq(seq)
            mitigation_id = _check_id(mitigation_id, "mitigation_id")
            rec = self._mitigations.get(mitigation_id)
            if rec is None:
                raise UnknownMitigationError(f"unknown mitigation: {mitigation_id!r}")
            return rec

    def assessments_for(self, system_id: str, seq: int) -> Tuple[AssessmentRecord, ...]:
        with self._lock:
            _check_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            return tuple(
                self._assessments[aid]
                for aid in self._system_assessments.get(system_id, [])
            )

    def mitigations_for(self, assessment_id: str, seq: int) -> Tuple[MitigationRecord, ...]:
        with self._lock:
            _check_read_seq(seq)
            assessment_id = _check_id(assessment_id, "assessment_id")
            return tuple(
                self._mitigations[mid]
                for mid in self._assessment_mitigations.get(assessment_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(sorted(self._system_assessments))

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(sorted(self._assessments))

    def mitigation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(sorted(self._mitigations))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            _check_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_assessments),
                "n_assessments": len(self._assessments),
                "n_mitigations": len(self._mitigations),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# stdlib-only self check
# ---------------------------------------------------------------------------


def stdlib_only() -> bool:
    """AST self-check: this module must import stdlib modules only."""
    import ast
    import pathlib

    allowed = {
        "__future__",
        "ast",
        "canonical_json",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
    }
    tree = ast.parse(pathlib.Path(__file__).read_text())
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
    """Self-check: exercise assess/mitigate/verify/evaluate/retire."""
    ledger = AIHarm()
    rec = ledger.assess("sys-1", 1, "physical-harm", "harm-detected", 40)
    assert rec.verify()
    mit = ledger.mitigate(rec.assessment_id, 2, "remediation")
    assert mit.verify()
    rep = ledger.verify(rec.assessment_id, 3)
    assert rep.verdict == "verified"
    evl = ledger.evaluate("sys-1", 4)
    assert evl.posture == "mitigated"
    assert evl.verify()
    ledger.retire("sys-1", 5)
    assert stdlib_only()
    print("ai-harm OK: assess, mitigate, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
