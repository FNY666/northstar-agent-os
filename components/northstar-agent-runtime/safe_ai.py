"""Safe AI: safety-assurance decision ledger, Simulated.

Research note: "safe AI" in the assurance literature (NIST AI Risk
Management Framework; frontier safety frameworks; safety-case practice)
is not a property any benchmark can measure directly - it is a *claim*
built out of declared evidence: which safety dimensions were assessed,
what assessment outcomes were declared, what independent verifications
were booked against those assessments, and what safety posture the
ledger derives from them. This module is the *decision ledger* for that
claim: declared safety assessments over a pinned dimension vocabulary,
declared verifications over a pinned verdict vocabulary, and a
ledger-rule safety posture - defensible bookkeeping, never proof that a
system is really safe.

This module owns the assess -> verify -> evaluate lifecycle:

* **assess()** - book one declared safety assessment (minted ``ass-N``
  ids; pinned 8-dimension vocabulary covering the standard safety
  practices; pinned outcome vocabulary booked *as data*); the first
  assessment registers its system; raw evidence, incident details, and
  vulnerability specifics never enter records - digest pins only.
* **verify()** - book one declared verification of an assessment
  (minted ``vfy-N`` ids; pinned verdict vocabulary - booked as data,
  never proof the verification really happened; one verification per
  assessment).
* **evaluate()** - **pure read**: derive one system's safety posture as
  data (``unassessed`` -> ``unsafe`` -> ``at-risk`` -> ``inconclusive``
  -> ``safe``) with outcome tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_safety.py`` owns the
safety-*issue* lifecycle (assess -> mitigate: declare a hazard, book its
mitigation); ``ai_alignment.py`` owns alignment assessments;
``responsible_ai.py`` / ``trustworthy_ai.py`` own their own
governance-flavored ledgers - this module is the *safety-assurance*
ledger none of them own: declared assessment claims, declared
independent verifications of those claims, and the ledger-rule safety
posture that turns booked claims into a safety claim ("no known safety
gap"), always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
a ``safe-ai.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no systems, performs no safety
assessments, verifies no claims, and proves nothing about real safety.
A booked ``satisfactory`` outcome means "the host declared it", never
"the system is safe". Raw evidence, incident reports, vulnerability
details, and exploit material never enter records or cross the audit
boundary - digest pins only.
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
SAFE_AI_VERSION = "safe-ai.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.safe-ai.v1"

#: Pinned safety-assessment dimension vocabulary (standard safety practices).
DIMENSIONS = (
    "robustness",
    "oversight",
    "containment",
    "monitoring",
    "incident-response",
    "evaluation",
    "transparency",
    "secure-deployment",
)

#: Pinned assessment-outcome vocabulary (booked as data, never proof).
ASSESS_OUTCOMES = (
    "satisfactory",
    "deficient",
    "critical-gap",
    "inconclusive",
    "not-assessed",
)

#: Pinned verification-verdict vocabulary (booked as data, never proof).
VERIFY_VERDICTS = (
    "substantiated",
    "refuted",
    "inconclusive",
    "not-checked",
)

#: Pinned derived safety postures (booked as data).
POSTURES = (
    "unassessed",
    "unsafe",
    "at-risk",
    "inconclusive",
    "safe",
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
    "verified",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
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
        "evidence",
        "evidence_text",
        "assessment_text",
        "notes",
        "raw",
        "incident",
        "incidents",
        "incident_report",
        "vulnerability",
        "vulnerabilities",
        "exploit",
        "exploits",
        "attack",
        "attacks",
        "threat",
        "threats",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class SafeAIError(Exception):
    """Base class for all safe-ai errors."""


class BadSystemError(SafeAIError):
    """system_id is not a non-empty string."""


class UnknownSystemError(SafeAIError):
    """No such system is registered in the ledger."""


class RetiredSystemError(SafeAIError):
    """The system is retired; mutations are refused."""


class DuplicateSystemError(SafeAIError):
    """A retired system id may never be re-registered."""


class BadDimensionError(SafeAIError):
    """dimension is not in the pinned vocabulary."""


class BadOutcomeError(SafeAIError):
    """outcome is not in the pinned vocabulary."""


class BadVerdictError(SafeAIError):
    """verdict is not in the pinned vocabulary."""


class BadDigestError(SafeAIError):
    """A digest pin is malformed (must be '' or 'sha256:' + 64 hex)."""


class BadReasonError(SafeAIError):
    """reason is not in the pinned vocabulary."""


class UnknownAssessmentError(SafeAIError):
    """No such assessment id is booked in the ledger."""


class AlreadyVerifiedError(SafeAIError):
    """An assessment may carry at most one verification."""


class SeqOrderError(SafeAIError):
    """seq is not a strictly increasing int (claim-then-burn)."""


class AuditKindError(SafeAIError):
    """Unknown audit kind requested from the audit builder."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_dimension(value: Any) -> str:
    if value not in DIMENSIONS:
        raise BadDimensionError(f"dimension must be one of {DIMENSIONS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in ASSESS_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {ASSESS_OUTCOMES}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in VERIFY_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {VERIFY_VERDICTS}")
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


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    system_id: str
    seq: int
    dimension: str
    outcome: str
    assessment_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_assess_payload(self), "safe-ai.assess")


@dataclass(frozen=True)
class VerificationRecord:
    verification_id: str
    assessment_id: str
    seq: int
    verdict: str
    verification_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_verify_payload(self), "safe-ai.verify")


@dataclass(frozen=True)
class VerificationReport:
    assessment_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_report_payload(self), "safe-ai.verify-report"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "safe-ai.retire")


@dataclass(frozen=True)
class SafetyReport:
    system_id: str
    seq: int
    posture: str
    n_assessments: int
    n_satisfactory: int
    n_deficient: int
    n_critical_gap: int
    n_inconclusive: int
    n_not_assessed: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_evaluate_payload(self), "safe-ai.evaluate")


def _assess_payload(rec: "AssessmentRecord") -> Dict[str, Any]:
    return {
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "dimension": rec.dimension,
        "outcome": rec.outcome,
        "assessment_digest": rec.assessment_digest,
    }


def _verify_payload(rec: "VerificationRecord") -> Dict[str, Any]:
    return {
        "verification_id": rec.verification_id,
        "assessment_id": rec.assessment_id,
        "seq": rec.seq,
        "verdict": rec.verdict,
        "verification_digest": rec.verification_digest,
    }


def _verify_report_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "assessment_id": rep.assessment_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _evaluate_payload(rep: "SafetyReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_assessments": rep.n_assessments,
        "n_satisfactory": rep.n_satisfactory,
        "n_deficient": rep.n_deficient,
        "n_critical_gap": rep.n_critical_gap,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_assessed": rep.n_not_assessed,
        "integrity_ok": rep.integrity_ok,
    }


def safe_ai_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise SafeAIError(f"raw key {key!r} may not cross the audit boundary")
    return {
        "schema": "audit.ndjson/1",
        "module": "safe-ai",
        "version": SAFE_AI_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class SafeAI:
    """Safe-AI assurance decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that a system is really safe.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._system_assessments: Dict[str, List[str]] = {}
        self._verifications: Dict[str, VerificationRecord] = {}
        self._assessment_verification: Dict[str, str] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assessment_counter = 0
        self._verification_counter = 0
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
            row = safe_ai_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(safe_ai_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        dimension: str = "robustness",
        outcome: str = "not-assessed",
        assessment_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared safety assessment; mint an ``ass-N`` id.

        The first assessment on an id registers the system. Raw evidence,
        incident details, and vulnerability specifics never enter records
        - digest pins only. Fail-closed: failed mutations consume their
        seq and book a ``safe-ai.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                dimension = _check_dimension(dimension)
                outcome = _check_outcome(outcome)
                assessment_digest = _check_digest(assessment_digest, "assessment_digest")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system is retired: {system_id!r}")
            except SafeAIError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._assessment_counter += 1
            assessment_id = f"ass-{self._assessment_counter}"
            provisional = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                dimension=dimension,
                outcome=outcome,
                assessment_digest=assessment_digest,
                digest="",
            )
            digest = _digest_pin(_assess_payload(provisional), "safe-ai.assess")
            rec = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                dimension=dimension,
                outcome=outcome,
                assessment_digest=assessment_digest,
                digest=digest,
            )
            self._assessments[assessment_id] = rec
            self._system_assessments.setdefault(system_id, []).append(assessment_id)
            self._emit(
                "assessed",
                seq,
                assessment_id=assessment_id,
                system_id=system_id,
                dimension=dimension,
                outcome=outcome,
                assessment_digest=assessment_digest,
            )
            return rec

    def verify(
        self,
        assessment_id: str,
        seq: int,
        verdict: str = "not-checked",
        verification_digest: str = "",
    ) -> VerificationRecord:
        """Book one declared verification of an assessment; mint ``vfy-N``.

        At most one verification per assessment (``AlreadyVerifiedError``).
        Verdicts are booked as data, never proof the verification really
        happened. Fail-closed on unknown assessments and retired
        systems.
        """
        with self._lock:
            try:
                if (
                    isinstance(assessment_id, bool)
                    or not isinstance(assessment_id, str)
                    or not assessment_id
                ):
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}"
                    )
                self._require_seq(seq)
                verdict = _check_verdict(verdict)
                verification_digest = _check_digest(
                    verification_digest, "verification_digest"
                )
                rec = self._assessments.get(assessment_id)
                if rec is None:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}"
                    )
                self._require_live(rec.system_id)
                if assessment_id in self._assessment_verification:
                    raise AlreadyVerifiedError(
                        f"assessment already verified: {assessment_id!r}"
                    )
            except SafeAIError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._verification_counter += 1
            verification_id = f"vfy-{self._verification_counter}"
            provisional = VerificationRecord(
                verification_id=verification_id,
                assessment_id=assessment_id,
                seq=seq,
                verdict=verdict,
                verification_digest=verification_digest,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "safe-ai.verify")
            vrec = VerificationRecord(
                verification_id=verification_id,
                assessment_id=assessment_id,
                seq=seq,
                verdict=verdict,
                verification_digest=verification_digest,
                digest=digest,
            )
            self._verifications[verification_id] = vrec
            self._assessment_verification[assessment_id] = verification_id
            self._emit(
                "verified",
                seq,
                verification_id=verification_id,
                assessment_id=assessment_id,
                verdict=verdict,
                verification_digest=verification_digest,
            )
            return vrec

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_assessments:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except SafeAIError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "safe-ai.retire")
            rec = RetireRecord(system_id=system_id, seq=seq, reason=reason, digest=digest)
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _require_assessment(self, assessment_id: str) -> AssessmentRecord:
        rec = self._assessments.get(assessment_id)
        if rec is None:
            raise UnknownAssessmentError(f"unknown assessment: {assessment_id!r}")
        return rec

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._assessments[aid].verify()
            for aid in self._system_assessments.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "satisfactory": 0,
            "deficient": 0,
            "critical-gap": 0,
            "inconclusive": 0,
            "not-assessed": 0,
        }
        for aid in self._system_assessments.get(system_id, []):
            tallies[self._assessments[aid].outcome] += 1
        n_assessments = sum(tallies.values())
        if n_assessments == 0:
            posture = "unassessed"
        elif tallies["critical-gap"]:
            posture = "unsafe"
        elif tallies["deficient"]:
            posture = "at-risk"
        elif tallies["inconclusive"]:
            posture = "inconclusive"
        else:
            posture = "safe"
        return posture, tallies

    def verify_assessment(self, assessment_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one assessment's digest pin.

        Verdict ``substantiated`` / ``refuted`` style ``verified`` /
        ``tampered`` booked as data (tamper is reported, never raised).
        Seq shape is validated, never consumed, and no audit row is
        booked.
        """
        with self._lock:
            seq = self._require_read_seq(seq)
            if (
                isinstance(assessment_id, bool)
                or not isinstance(assessment_id, str)
                or not assessment_id
            ):
                raise UnknownAssessmentError(f"unknown assessment: {assessment_id!r}")
            rec = self._require_assessment(assessment_id)
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                assessment_id=assessment_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _verify_report_payload(provisional), "safe-ai.verify-report"
            )
            return VerificationReport(
                assessment_id=assessment_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> SafetyReport:
        """Pure read: derive one system's safety posture as data.

        Posture rule: ``unassessed`` (no assessments) -> ``unsafe``
        (any ``critical-gap``) -> ``at-risk`` (any ``deficient``) ->
        ``inconclusive`` (any ``inconclusive``) -> ``safe`` (everything
        else). Seq shape validated, never consumed; no audit rows.
        """
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_assessments:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            integrity_ok = self._integrity_ok(system_id)
            provisional = SafetyReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=sum(tallies.values()),
                n_satisfactory=tallies["satisfactory"],
                n_deficient=tallies["deficient"],
                n_critical_gap=tallies["critical-gap"],
                n_inconclusive=tallies["inconclusive"],
                n_not_assessed=tallies["not-assessed"],
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "safe-ai.evaluate")
            return SafetyReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=sum(tallies.values()),
                n_satisfactory=tallies["satisfactory"],
                n_deficient=tallies["deficient"],
                n_critical_gap=tallies["critical-gap"],
                n_inconclusive=tallies["inconclusive"],
                n_not_assessed=tallies["not-assessed"],
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views ---------------------------------------------------------------

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        """Pure read: fetch one booked assessment record."""
        with self._lock:
            self._require_read_seq(seq)
            return self._require_assessment(assessment_id)

    def verification_record(self, verification_id: str, seq: int) -> VerificationRecord:
        """Pure read: fetch one booked verification record."""
        with self._lock:
            self._require_read_seq(seq)
            rec = self._verifications.get(verification_id)
            if rec is None:
                raise UnknownAssessmentError(
                    f"unknown verification: {verification_id!r}"
                )
            return rec

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        """Pure read: fetch one booked retirement record."""
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            rec = self._retired.get(system_id)
            if rec is None:
                raise UnknownSystemError(f"system not retired: {system_id!r}")
            return rec

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all registered system ids."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_assessments))

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all minted assessment ids."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                sorted(self._assessments, key=lambda a: int(a.split("-")[1]))
            )

    def verification_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all minted verification ids."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                sorted(self._verifications, key=lambda v: int(v.split("-")[1]))
            )

    def assessments_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read: assessment ids booked for one system."""
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_assessments:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(self._system_assessments[system_id])

    def verification_for(self, assessment_id: str, seq: int) -> str:
        """Pure read: the verification id booked for one assessment."""
        with self._lock:
            self._require_read_seq(seq)
            self._require_assessment(assessment_id)
            vid = self._assessment_verification.get(assessment_id)
            if vid is None:
                raise UnknownAssessmentError(
                    f"assessment not verified: {assessment_id!r}"
                )
            return vid

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: retired system ids."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger tallies."""
        with self._lock:
            self._require_read_seq(seq)
            return {
                "schema": SCHEMA_PIN,
                "version": SAFE_AI_VERSION,
                "seq": self._seq,
                "n_systems": len(self._system_assessments),
                "n_assessments": len(self._assessments),
                "n_verifications": len(self._verifications),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the audit rows booked so far."""
        with self._lock:
            self._require_read_seq(seq)
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
    """Self-check: exercise assess/verify/evaluate/retire and print status."""
    assert stdlib_only(), "stdlib-only AST self-check failed"
    ledger = SafeAI()
    rec = ledger.assess("sys-1", 1, dimension="monitoring", outcome="satisfactory")
    assert rec.verify()
    vrec = ledger.verify(rec.assessment_id, 2, verdict="substantiated")
    assert vrec.verify()
    assert ledger.verify_assessment(rec.assessment_id, 3).verdict == "verified"
    assert ledger.evaluate("sys-1", 4).posture == "safe"
    ledger.retire("sys-1", 5)
    print("safe-ai OK: assess, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
