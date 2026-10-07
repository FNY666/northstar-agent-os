"""AI ethics verification: ethics-check verification decision ledger, Simulated.

Research note: ethics verification is the discipline of checking that a
system satisfies its declared ethical commitments - that the ethics
checks the host says it ran really say what the host says they say.
This module is the *decision ledger* for declared AI-ethics
verifications: which subjects had which ethics checks booked (over a
pinned check-kind vocabulary), what verdicts were declared against
them, what certifications the host declared over those verifications,
and what ethics-verification posture the ledger derives - defensible
bookkeeping, never proof that a system is really ethical.

This module owns the verify -> certify -> evaluate lifecycle:

* **verify()** - book one declared ethics verification (minted ``ver-N``
  ids; pinned check-kind vocabulary over the common AI-ethics
  verification classes: fairness reviews, bias screens, harm
  assessments, transparency reviews, accountability checks, consent
  verification, value-alignment reviews, stakeholder-impact reviews;
  pinned verdict vocabulary booked *as data*); the first verification
  registers its subject; raw review material, stakeholder testimony,
  deliberation traces, and survey data never enter records - digest
  pins only.
* **certify()** - book one declared certification against a booked
  verification (minted ``crt-N`` ids; pinned certification-kind
  vocabulary booked *as data*); certifies the *verification record*
  (an independent second look at the declared check), not the
  subject; repeatable chain; books the *declaration*, never the
  performed review.
* **evaluate()** - **pure read**: derive one subject's
  ethics-verification posture as data (``unverified`` -> ``failed`` ->
  ``contested`` -> ``partially-verified`` -> ``verified`` ->
  ``certified``) with verdict tallies and a digest-pinned integrity
  flag.
* **retire()** - terminal retirement of a subject id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_verification.py`` owns the
generic verification/certification lifecycle (build-vs-spec checks);
``ai_ethics.py`` owns the ethics *assessment* lifecycle; ``ai_safety.py``
owns the safety assessment->mitigation lifecycle;
``ai_safety_verification.py`` owns the AI-*safety* verification
lifecycle (safety-property, hazard-analysis, fault-injection checks -
checks against safety hazards, not ethical commitments);
``ai_certification.py`` owns the third-party *attestation* lifecycle
(certifying subjects against standards); ``ai_fairness.py`` and
``ai_bias.py`` own the fairness/bias assessment->mitigation ledgers -
this module is the AI-*ethics* verification decision ledger none of
them own: declared ethics checks against ethical commitments, declared
certifications of those checks, digest re-derivation, and the
ledger-rule posture that turns declared verdicts into an
ethics-verification claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-ethics-verification.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no checks, inspects no systems,
performs no reviews, and proves nothing about real AI ethics. A booked
``verified`` verdict means "the host declared it", never "the system is
verified ethical"; a booked certification means "the host declared it",
never "the check was really reviewed". Review material, stakeholder
testimony, deliberation transcripts, survey data, harm narratives, and
raw verification material never enter records or cross the audit
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
AI_ETHICS_VERIFICATION_VERSION = "ai-ethics-verification.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-ethics-verification.v1"

#: Pinned ethics-check-kind vocabulary (the ethics checks declared).
CHECK_KINDS = (
    "fairness-review",
    "bias-screen",
    "harm-assessment",
    "transparency-review",
    "accountability-check",
    "consent-verification",
    "value-alignment-review",
    "stakeholder-impact-review",
)

#: Pinned verification-verdict vocabulary (booked as data, never proof).
VERIFY_VERDICTS = (
    "verified",
    "partial",
    "failed",
    "inconclusive",
    "not-verified",
)

#: Pinned certification-kind vocabulary (booked as data, never proof).
CERTIFICATION_KINDS = (
    "independent-review",
    "third-party-audit",
    "regulator-approval",
    "peer-review",
    "internal-qa",
    "external-lab",
    "standards-body",
    "self-attestation",
)

#: Pinned certification-outcome vocabulary (booked as data, never proof).
CERTIFICATION_OUTCOMES = (
    "endorsed",
    "qualified",
    "withheld",
    "inconclusive",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unverified",
    "failed",
    "contested",
    "partially-verified",
    "verified",
    "certified",
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
    "verified",
    "certified",
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
        "proof_script",
        "proof_scripts",
        "workpaper",
        "workpapers",
        "reviewer",
        "reviewers",
        "auditor",
        "auditors",
        "artifact_bytes",
        "artifacts",
        "crash_report",
        "crash_reports",
        "check_script",
        "verification_log",
        "verification_logs",
        "ethics_report",
        "ethics_review",
        "stakeholder_feedback",
        "stakeholder_testimony",
        "survey_data",
        "survey_responses",
        "interview_notes",
        "deliberation_transcript",
        "deliberation_notes",
        "harm_narrative",
        "harm_description",
        "complaint_text",
        "appeal_text",
        "bias_report",
        "fairness_audit_data",
        "consent_record",
        "consent_form",
        "voter_record",
        "review_notes",
        "ethics_case",
        "case_file",
        "certificate",
        "certificates",
        "seal",
        "signature",
        "api_key",
        "password",
        "secret",
        "token",
        "private_key",
        "pii",
        "personal_data",
        "user_data",
        "name",
        "email",
        "address",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIEthicsVerificationError(Exception):
    """Base class for all ai-ethics-verification ledger errors."""


class BadSubjectError(AIEthicsVerificationError):
    pass


class UnknownSubjectError(AIEthicsVerificationError):
    pass


class RetiredSubjectError(AIEthicsVerificationError):
    pass


class BadCheckKindError(AIEthicsVerificationError):
    pass


class BadVerdictError(AIEthicsVerificationError):
    pass


class BadSeverityError(AIEthicsVerificationError):
    pass


class BadDigestError(AIEthicsVerificationError):
    pass


class BadReasonError(AIEthicsVerificationError):
    pass


class UnknownVerificationError(AIEthicsVerificationError):
    pass


class UnknownCertificationError(AIEthicsVerificationError):
    pass


class UnknownRecordError(AIEthicsVerificationError):
    pass


class BadCertificationKindError(AIEthicsVerificationError):
    pass


class BadOutcomeError(AIEthicsVerificationError):
    pass


class SeqOrderError(AIEthicsVerificationError):
    pass


class AuditKindError(AIEthicsVerificationError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSubjectError(f"{what} must be a non-empty string")
    return value


def _check_check_kind(value: Any) -> str:
    if value not in CHECK_KINDS:
        raise BadCheckKindError(f"check_kind must be one of {CHECK_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in VERIFY_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {VERIFY_VERDICTS}")
    return value


def _check_certification_kind(value: Any) -> str:
    if value not in CERTIFICATION_KINDS:
        raise BadCertificationKindError(
            f"certification_kind must be one of {CERTIFICATION_KINDS}"
        )
    return value


def _check_outcome(value: Any) -> str:
    if value not in CERTIFICATION_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {CERTIFICATION_OUTCOMES}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int")
    if not 0 <= value <= 100:
        raise BadSeverityError("severity must be in [0, 100]")
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
class VerificationRecord:
    verification_id: str
    subject_id: str
    seq: int
    check_kind: str
    verdict: str
    severity: int
    verification_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-ethics-verification.verify"
        )


@dataclass(frozen=True)
class CertificationRecord:
    certification_id: str
    verification_id: str
    subject_id: str
    seq: int
    certification_kind: str
    outcome: str
    certification_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _certify_payload(self), "ai-ethics-verification.certify"
        )


@dataclass(frozen=True)
class RetireRecord:
    subject_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-ethics-verification.retire"
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
            _verify_report_payload(self), "ai-ethics-verification.verify-report"
        )


@dataclass(frozen=True)
class EvaluationReport:
    subject_id: str
    seq: int
    posture: str
    n_verifications: int
    n_verified: int
    n_partial: int
    n_failed: int
    n_inconclusive: int
    n_not_verified: int
    n_certified: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-ethics-verification.evaluate"
        )


def _verify_payload(rec: "VerificationRecord") -> Dict[str, Any]:
    return {
        "verification_id": rec.verification_id,
        "subject_id": rec.subject_id,
        "seq": rec.seq,
        "check_kind": rec.check_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "verification_digest": rec.verification_digest,
    }


def _certify_payload(rec: "CertificationRecord") -> Dict[str, Any]:
    return {
        "certification_id": rec.certification_id,
        "verification_id": rec.verification_id,
        "subject_id": rec.subject_id,
        "seq": rec.seq,
        "certification_kind": rec.certification_kind,
        "outcome": rec.outcome,
        "certification_digest": rec.certification_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"subject_id": rec.subject_id, "seq": rec.seq, "reason": rec.reason}


def _verify_report_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "subject_id": rep.subject_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_verifications": rep.n_verifications,
        "n_verified": rep.n_verified,
        "n_partial": rep.n_partial,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_verified": rep.n_not_verified,
        "n_certified": rep.n_certified,
        "integrity_ok": rep.integrity_ok,
    }


def ai_ethics_verification_audit_event(
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
            raise AIEthicsVerificationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-ethics-verification",
        "version": AI_ETHICS_VERIFICATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIEthicsVerification:
    """AI-ethics verification decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and
    certifications are booked as data - never proof that a system is
    really ethical.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._verifications: Dict[str, VerificationRecord] = {}
        self._certifications: Dict[str, CertificationRecord] = {}
        self._subject_verifications: Dict[str, List[str]] = {}
        self._verification_certifications: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._verification_counter = 0
        self._certification_counter = 0
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
            row = ai_ethics_verification_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-ethics-verification",
                "version": AI_ETHICS_VERIFICATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_ethics_verification_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, subject_id: str) -> None:
        if subject_id in self._retired:
            raise RetiredSubjectError(f"subject is retired: {subject_id!r}")

    # -- mutations ---------------------------------------------------------

    def verify(
        self,
        subject_id: str,
        seq: int,
        check_kind: str = "fairness-review",
        verdict: str = "not-verified",
        severity: int = 0,
        verification_digest: str = "",
    ) -> VerificationRecord:
        """Book one declared ethics verification (minted ``ver-N`` id).

        The first verification on an id registers the subject. Raw
        review material, stakeholder testimony, deliberation traces,
        and survey data never enter records - digest pins only.
        Fail-closed: failed mutations consume their seq and book an
        ``ai-ethics-verification.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                subject_id = _check_id(subject_id, "subject_id")
                self._require_seq(seq)
                check_kind = _check_check_kind(check_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                verification_digest = _check_digest(
                    verification_digest, "verification_digest"
                )
                self._require_live(subject_id)
            except AIEthicsVerificationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._verification_counter += 1
            verification_id = f"ver-{self._verification_counter}"
            provisional = VerificationRecord(
                verification_id=verification_id,
                subject_id=subject_id,
                seq=seq,
                check_kind=check_kind,
                verdict=verdict,
                severity=severity,
                verification_digest=verification_digest,
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-ethics-verification.verify"
            )
            rec = VerificationRecord(
                verification_id=verification_id,
                subject_id=subject_id,
                seq=seq,
                check_kind=check_kind,
                verdict=verdict,
                severity=severity,
                verification_digest=verification_digest,
                digest=digest,
            )
            self._verifications[verification_id] = rec
            self._subject_verifications.setdefault(subject_id, []).append(
                verification_id
            )
            self._emit(
                "verified",
                seq,
                verification_id=verification_id,
                subject_id=subject_id,
                check_kind=check_kind,
                verdict=verdict,
                severity=severity,
            )
            return rec

    def certify(
        self,
        verification_id: str,
        seq: int,
        certification_kind: str = "independent-review",
        outcome: str = "endorsed",
        certification_digest: str = "",
    ) -> CertificationRecord:
        """Book one declared certification against a booked verification.

        Minted ``crt-N`` id. Certifies the *verification record* (an
        independent second look at the declared check), not the subject.
        Books the *declaration*, never the performed review. Repeatable
        as a chain. Fail-closed: failed mutations consume their seq and
        book an ``ai-ethics-verification.rejected`` row; rewinds raise
        bare.
        """
        with self._lock:
            try:
                verification_id = _check_id(verification_id, "verification_id")
                self._require_seq(seq)
                certification_kind = _check_certification_kind(certification_kind)
                outcome = _check_outcome(outcome)
                certification_digest = _check_digest(
                    certification_digest, "certification_digest"
                )
                verification = self._verifications.get(verification_id)
                if verification is None:
                    raise UnknownVerificationError(
                        f"unknown verification: {verification_id!r}"
                    )
                self._require_live(verification.subject_id)
            except AIEthicsVerificationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._certification_counter += 1
            certification_id = f"crt-{self._certification_counter}"
            provisional = CertificationRecord(
                certification_id=certification_id,
                verification_id=verification_id,
                subject_id=verification.subject_id,
                seq=seq,
                certification_kind=certification_kind,
                outcome=outcome,
                certification_digest=certification_digest,
                digest="",
            )
            digest = _digest_pin(
                _certify_payload(provisional), "ai-ethics-verification.certify"
            )
            rec = CertificationRecord(
                certification_id=certification_id,
                verification_id=verification_id,
                subject_id=verification.subject_id,
                seq=seq,
                certification_kind=certification_kind,
                outcome=outcome,
                certification_digest=certification_digest,
                digest=digest,
            )
            self._certifications[certification_id] = rec
            self._verification_certifications.setdefault(verification_id, []).append(
                certification_id
            )
            self._emit(
                "certified",
                seq,
                certification_id=certification_id,
                verification_id=verification_id,
                subject_id=verification.subject_id,
                certification_kind=certification_kind,
                outcome=outcome,
            )
            return rec

    def retire(
        self, subject_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a subject id; ids are never recycled."""
        with self._lock:
            try:
                subject_id = _check_id(subject_id, "subject_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if subject_id not in self._subject_verifications:
                    raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
                if subject_id in self._retired:
                    raise RetiredSubjectError(
                        f"subject already retired: {subject_id!r}"
                    )
            except AIEthicsVerificationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                subject_id=subject_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-ethics-verification.retire"
            )
            rec = RetireRecord(
                subject_id=subject_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[subject_id] = rec
            self._emit("retired", seq, subject_id=subject_id, reason=reason)
            return rec

    # -- pure reads ----------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, subject_id: str) -> bool:
        return all(
            self._verifications[vid].verify()
            and all(
                self._certifications[cid].verify()
                for cid in self._verification_certifications.get(vid, [])
            )
            for vid in self._subject_verifications.get(subject_id, [])
        )

    def _certification_outcomes(self, verification_id: str) -> List[str]:
        return [
            self._certifications[cid].outcome
            for cid in self._verification_certifications.get(verification_id, [])
        ]

    def _posture(self, subject_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "verified": 0,
            "partial": 0,
            "failed": 0,
            "inconclusive": 0,
            "not-verified": 0,
            "certified": 0,
        }
        ids = self._subject_verifications.get(subject_id, [])
        for vid in ids:
            rec = self._verifications[vid]
            tallies[rec.verdict] += 1
            if "endorsed" in self._certification_outcomes(vid):
                tallies["certified"] += 1
        if not ids:
            return "unverified", tallies
        # A failed verdict, or any withheld certification, fails the subject.
        if tallies["failed"]:
            return "failed", tallies
        if any(
            "withheld" in self._certification_outcomes(vid) for vid in ids
        ):
            return "failed", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["partial"] or tallies["not-verified"]:
            return "partially-verified", tallies
        if all(self._verifications[vid].verdict == "verified" for vid in ids):
            if all(
                "endorsed" in self._certification_outcomes(vid) for vid in ids
            ):
                return "certified", tallies
            return "verified", tallies
        return "contested", tallies

    def verify_report(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._verifications.get(record_id) or self._certifications.get(
                record_id
            )
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
                _verify_report_payload(provisional),
                "ai-ethics-verification.verify-report",
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, subject_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one subject's ethics-verification posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            subject_id = _check_id(subject_id, "subject_id")
            if subject_id not in self._subject_verifications:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            posture, tallies = self._posture(subject_id)
            provisional = EvaluationReport(
                subject_id=subject_id,
                seq=seq,
                posture=posture,
                n_verifications=len(self._subject_verifications[subject_id]),
                n_verified=tallies["verified"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                n_not_verified=tallies["not-verified"],
                n_certified=tallies["certified"],
                integrity_ok=self._integrity_ok(subject_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-ethics-verification.evaluate"
            )
            return EvaluationReport(
                subject_id=subject_id,
                seq=seq,
                posture=posture,
                n_verifications=len(self._subject_verifications[subject_id]),
                n_verified=tallies["verified"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                n_not_verified=tallies["not-verified"],
                n_certified=tallies["certified"],
                integrity_ok=self._integrity_ok(subject_id),
                digest=digest,
            )

    # -- views (pure reads) ----------------------------------------------------

    def verification_record(self, verification_id: str, seq: int) -> VerificationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._verifications.get(verification_id)
            if rec is None:
                raise UnknownVerificationError(
                    f"unknown verification: {verification_id!r}"
                )
            return rec

    def certification_record(
        self, certification_id: str, seq: int
    ) -> CertificationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._certifications.get(certification_id)
            if rec is None:
                raise UnknownCertificationError(
                    f"unknown certification: {certification_id!r}"
                )
            return rec

    def verifications_for(self, subject_id: str, seq: int) -> Tuple[VerificationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._verifications[vid]
                for vid in self._subject_verifications.get(subject_id, [])
            )

    def certifications_for(
        self, verification_id: str, seq: int
    ) -> Tuple[CertificationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._certifications[cid]
                for cid in self._verification_certifications.get(verification_id, [])
            )

    def subject_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._subject_verifications.keys()))

    def verification_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._verifications.keys()))

    def certification_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._certifications.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_subjects": len(self._subject_verifications),
                "n_verifications": len(self._verifications),
                "n_certifications": len(self._certifications),
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
    """Self-check: exercise verify -> certify -> verify_report -> evaluate."""
    ledger = AIEthicsVerification()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.verify(
        "sys-1", 1, check_kind="fairness-review", verdict="verified", severity=5
    )
    assert rec.verify()
    crt = ledger.certify(
        rec.verification_id, 2, certification_kind="independent-review",
        outcome="endorsed",
    )
    assert crt.verify()
    rep = ledger.verify_report(rec.verification_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "certified"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-ethics-verification OK: verify, certify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
