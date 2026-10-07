"""AI verification: verify/certify decision ledger, Simulated.

Research note: verification is the AI assurance claim layer - the host
declares which subjects (models, policies, deployments, code artifacts)
had which declared verification runs booked against them (over a
pinned check-kind vocabulary, with declared verdicts and
host-reported severity), declares which verification records were
independently certified (over a pinned certification-kind vocabulary,
with declared endorsement outcomes), and derives a ledger-rule
verification posture - defensible bookkeeping, never proof that the
subject was really checked, that a check was really independent, or
that the declaration matches the real world.

This module owns the verify -> certify -> evaluate lifecycle:

* **verify()** - book one declared verification run (minted ``ver-N``
  ids; pinned check-kind vocabulary; pinned verdict vocabulary;
  host-reported severity); the first verify registers its subject;
  raw artifacts, proof scripts, test logs, and check harnesses never
  enter records - digest pins only.
* **certify()** - book one declared certification of a verification
  record (minted ``crt-N`` ids; pinned certification-kind vocabulary;
  declared endorsement outcome); chainable; fail-closed on unknown
  verification records or retired subjects.
* **evaluate()** - **pure read**: derive one subject's verification
  posture as data (``failed`` -> ``contested`` -> ``partially-verified``
  -> ``verified`` -> ``certified``) with verification/certification
  tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a subject id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_certification.py`` owns
the third-party *attestation* lifecycle (certifying subjects/systems
against declared standards with declared outcomes);
``data_validation.py`` owns data-pipeline validation;
``remote_attestation.py`` owns remote attestation mechanics;
``ai_monitoring.py`` owns declared monitoring watches; this module is
the *verification-record* decision ledger none of them own: declared
verification runs against subjects, declared certifications of those
verification records (not of the subjects themselves), digest
re-derivation, and the ledger-rule posture that turns declared
verifications and certifications into a verification claim, always as
data, never as measured verification truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-verification.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module verifies nothing real and proves nothing
about real-world behavior. A booked ``certified`` posture means "the
host declared it", never "the subject is really safe"; a booked
``endorsed`` certification means "the host declared it", never "an
independent party really signed off". Artifacts, proof scripts, test
logs, audit workpapers, reviewer identities, and lab reports never
enter records or cross the audit boundary - digest pins only.
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
AI_VERIFICATION_VERSION = "ai-verification.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-verification.v1"

#: Pinned verification check-kind vocabulary (booked as data).
CHECK_KINDS = (
    "formal-proof",
    "model-checking",
    "unit-test-suite",
    "property-test",
    "red-team-exercise",
    "static-analysis",
    "fuzzing-campaign",
    "human-audit",
)

#: Pinned verification-verdict vocabulary (booked as data, never proof
#: of real verification outcomes).
VERIFY_VERDICTS = (
    "verified",
    "failed",
    "inconclusive",
    "not-applicable",
    "not-verified",
)

#: Pinned certification-kind vocabulary (booked as data).
CERT_KINDS = (
    "peer-review",
    "independent-audit",
    "accreditation",
    "self-attestation",
    "third-party-lab",
    "red-team-review",
    "formal-certification",
    "continuous-monitoring",
)

#: Pinned certification-outcome vocabulary (booked as data).
CERT_OUTCOMES = (
    "endorsed",
    "qualified",
    "withheld",
    "inconclusive",
)

#: Pinned derived postures (booked as data), with precedence order
#: failed > contested > partially-verified > verified > certified.
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
    "withdrawn",
    "false-start",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
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
        "checkpoint",
        "artifact",
        "artifacts",
        "artifact_bytes",
        "source",
        "source_code",
        "proof",
        "proof_script",
        "proofs",
        "tactics",
        "model",
        "model_code",
        "counterexample",
        "counterexamples",
        "test_log",
        "test_logs",
        "test_results",
        "fuzzing_corpus",
        "crash_report",
        "crashes",
        "report",
        "report_text",
        "workpaper",
        "workpapers",
        "audit_report",
        "findings",
        "finding_details",
        "evidence",
        "trace",
        "traces",
        "trajectory",
        "transcript",
        "reviewer",
        "reviewer_id",
        "reviewer_identity",
        "auditor",
        "auditor_id",
        "lab_identity",
        "operator",
        "operator_id",
        "team",
        "payload",
        "payload_bytes",
        "prompt",
        "prompts",
        "output",
        "outputs",
        "response",
        "responses",
        "log",
        "logs",
        "dump",
        "dumps",
        "snapshot",
        "recording",
        "forensics",
        "root_cause",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "personal_data",
        "identity",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIVerificationError(Exception):
    """Base class for all ai-verification ledger errors."""


class BadSubjectError(AIVerificationError):
    pass


class UnknownSubjectError(AIVerificationError):
    pass


class RetiredSubjectError(AIVerificationError):
    pass


class BadCheckKindError(AIVerificationError):
    pass


class BadVerdictError(AIVerificationError):
    pass


class BadSeverityError(AIVerificationError):
    pass


class BadDigestError(AIVerificationError):
    pass


class BadReasonError(AIVerificationError):
    pass


class BadCertKindError(AIVerificationError):
    pass


class BadCertOutcomeError(AIVerificationError):
    pass


class UnknownRecordError(AIVerificationError):
    pass


class UnknownVerificationError(AIVerificationError):
    pass


class SeqOrderError(AIVerificationError):
    pass


class AuditKindError(AIVerificationError):
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


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int in [0, 100]")
    if value < 0 or value > 100:
        raise BadSeverityError("severity must be an int in [0, 100]")
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


def _check_cert_kind(value: Any) -> str:
    if value not in CERT_KINDS:
        raise BadCertKindError(f"certification_kind must be one of {CERT_KINDS}")
    return value


def _check_cert_outcome(value: Any) -> str:
    if value not in CERT_OUTCOMES:
        raise BadCertOutcomeError(f"outcome must be one of {CERT_OUTCOMES}")
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
class VerificationRecord:
    verification_id: str
    subject_id: str
    seq: int
    check_kind: str
    verdict: str
    severity: int
    artifact_digest: str
    verification_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verification_payload(self), "ai-verification.verify"
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
            _certification_payload(self), "ai-verification.certify"
        )


@dataclass(frozen=True)
class RetireRecord:
    subject_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-verification.retire"
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
            _verify_payload(self), "ai-verification.verify-report"
        )


@dataclass(frozen=True)
class EvaluationReport:
    subject_id: str
    seq: int
    posture: str
    n_verifications: int
    n_certifications: int
    n_failed: int
    n_endorsed: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-verification.evaluate"
        )


def _verification_payload(rec: "VerificationRecord") -> Dict[str, Any]:
    return {
        "verification_id": rec.verification_id,
        "subject_id": rec.subject_id,
        "seq": rec.seq,
        "check_kind": rec.check_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "artifact_digest": rec.artifact_digest,
        "verification_digest": rec.verification_digest,
    }


def _certification_payload(rec: "CertificationRecord") -> Dict[str, Any]:
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


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
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
        "n_certifications": rep.n_certifications,
        "n_failed": rep.n_failed,
        "n_endorsed": rep.n_endorsed,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_verification_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIVerificationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-verification",
        "version": AI_VERIFICATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIVerification:
    """AI-verification verify/certify decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All check kinds, verdicts,
    certification outcomes, and postures are booked as data - never
    proof that real verification or certification happened.
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
            row = ai_verification_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-verification",
                "version": AI_VERIFICATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_verification_audit_event(audit_kind, seq, **details))

    def _require_live(self, subject_id: str) -> None:
        if subject_id in self._retired:
            raise RetiredSubjectError(f"subject is retired: {subject_id!r}")

    # -- mutations ---------------------------------------------------------

    def verify(
        self,
        subject_id: str,
        seq: int,
        check_kind: str = "formal-proof",
        verdict: str = "not-verified",
        severity: int = 0,
        artifact_digest: str = "",
        verification_digest: str = "",
    ) -> VerificationRecord:
        """Book one declared verification run (minted ``ver-N`` id).

        The first verify on an id registers the subject. Raw artifacts,
        proof scripts, test logs, and check harnesses never enter
        records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an ``ai-verification.rejected`` row;
        rewinds raise bare.
        """
        with self._lock:
            try:
                subject_id = _check_id(subject_id, "subject_id")
                self._require_seq(seq)
                check_kind = _check_check_kind(check_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                artifact_digest = _check_digest(artifact_digest, "artifact_digest")
                verification_digest = _check_digest(
                    verification_digest, "verification_digest"
                )
                self._require_live(subject_id)
            except AIVerificationError as exc:
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
                artifact_digest=artifact_digest,
                verification_digest=verification_digest,
                digest="",
            )
            digest = _digest_pin(_verification_payload(provisional), "ai-verification.verify")
            rec = VerificationRecord(
                verification_id=verification_id,
                subject_id=subject_id,
                seq=seq,
                check_kind=check_kind,
                verdict=verdict,
                severity=severity,
                artifact_digest=artifact_digest,
                verification_digest=verification_digest,
                digest=digest,
            )
            self._verifications[verification_id] = rec
            self._subject_verifications.setdefault(subject_id, []).append(verification_id)
            self._emit(
                "verified",
                seq,
                verification_id=verification_id,
                subject_id=subject_id,
                check_kind=check_kind,
                verdict=verdict,
                severity=severity,
                artifact_digest=artifact_digest,
                verification_digest=verification_digest,
            )
            return rec

    def certify(
        self,
        verification_id: str,
        seq: int,
        certification_kind: str = "peer-review",
        outcome: str = "endorsed",
        certification_digest: str = "",
    ) -> CertificationRecord:
        """Book one declared certification of a verification record.

        Minted ``crt-N`` ids. Repeatable chain: many certifications may
        be booked against one verification record. The certification is
        of the *verification record*, not of the subject - this is the
        independent second look at the declared check. Fail-closed on
        unknown verification records or retired subjects.
        """
        with self._lock:
            try:
                verification_id = _check_id(verification_id, "verification_id")
                self._require_seq(seq)
                certification_kind = _check_cert_kind(certification_kind)
                outcome = _check_cert_outcome(outcome)
                certification_digest = _check_digest(
                    certification_digest, "certification_digest"
                )
                if verification_id not in self._verifications:
                    raise UnknownVerificationError(
                        f"unknown verification id: {verification_id!r}"
                    )
                subject_id = self._verifications[verification_id].subject_id
                self._require_live(subject_id)
            except AIVerificationError as exc:
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
                subject_id=subject_id,
                seq=seq,
                certification_kind=certification_kind,
                outcome=outcome,
                certification_digest=certification_digest,
                digest="",
            )
            digest = _digest_pin(
                _certification_payload(provisional), "ai-verification.certify"
            )
            rec = CertificationRecord(
                certification_id=certification_id,
                verification_id=verification_id,
                subject_id=subject_id,
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
                subject_id=subject_id,
                certification_kind=certification_kind,
                outcome=outcome,
                certification_digest=certification_digest,
            )
            return rec

    def retire(
        self, subject_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a subject id; ids are never recycled."""
        with self._lock:
            try:
                subject_id = _check_id(subject_id, "subject_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if subject_id in self._retired:
                    raise RetiredSubjectError(f"subject is retired: {subject_id!r}")
                if subject_id not in self._subject_verifications:
                    raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            except AIVerificationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                subject_id=subject_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-verification.retire")
            rec = RetireRecord(
                subject_id=subject_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[subject_id] = rec
            self._emit("retired", seq, subject_id=subject_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify_report(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one verification or certification record's
        digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the verification really happened. Seq is shape-validated
        only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            rec = self._verifications.get(record_id)
            if rec is None:
                rec = self._certifications.get(record_id)
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
                _verify_payload(provisional), "ai-verification.verify-report"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, subject_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one subject's verification posture as data.

        Posture by ledger rule: ``failed`` (any ``failed`` verdict, or
        any certification outcome ``withheld``) -> ``contested`` (any
        ``inconclusive`` verdict or certification outcome) ->
        ``partially-verified`` (mixed: some ``verified``, some not yet
        verified) -> ``verified`` (all verifications ``verified``, not
        all certified) -> ``certified`` (all verifications ``verified``
        and every verification carries at least one ``endorsed``
        certification). ``n_failed`` counts failed verifications;
        ``n_endorsed`` counts endorsed certifications. ``integrity_ok``
        re-derives all in-scope digest pins as data. Seq is
        shape-validated only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            subject_id = _check_id(subject_id, "subject_id")
            if subject_id not in self._subject_verifications:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            verification_ids = self._subject_verifications[subject_id]
            verifications = [self._verifications[i] for i in verification_ids]
            certifications: List[CertificationRecord] = []
            for vid in verification_ids:
                certifications.extend(
                    self._certifications[c]
                    for c in self._verification_certifications.get(vid, [])
                )
            n_failed = sum(1 for v in verifications if v.verdict == "failed")
            n_endorsed = sum(1 for c in certifications if c.outcome == "endorsed")
            endorsed_by_verification = {
                vid: any(
                    self._certifications[c].outcome == "endorsed"
                    for c in self._verification_certifications.get(vid, [])
                )
                for vid in verification_ids
            }
            if n_failed > 0 or any(c.outcome == "withheld" for c in certifications):
                posture = "failed"
            elif any(v.verdict == "inconclusive" for v in verifications) or any(
                c.outcome == "inconclusive" for c in certifications
            ):
                posture = "contested"
            elif all(v.verdict == "verified" for v in verifications):
                if all(endorsed_by_verification.values()):
                    posture = "certified"
                else:
                    posture = "verified"
            else:
                posture = "partially-verified"
            integrity_ok = all(v.verify() for v in verifications) and all(
                c.verify() for c in certifications
            )
            provisional = EvaluationReport(
                subject_id=subject_id,
                seq=seq,
                posture=posture,
                n_verifications=len(verifications),
                n_certifications=len(certifications),
                n_failed=n_failed,
                n_endorsed=n_endorsed,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-verification.evaluate"
            )
            return EvaluationReport(
                subject_id=subject_id,
                seq=seq,
                posture=posture,
                n_verifications=len(verifications),
                n_certifications=len(certifications),
                n_failed=n_failed,
                n_endorsed=n_endorsed,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def verification_record(self, verification_id: str, seq: int) -> VerificationRecord:
        with self._lock:
            self._check_read_seq(seq)
            if verification_id not in self._verifications:
                raise UnknownRecordError(
                    f"unknown verification id: {verification_id!r}"
                )
            return self._verifications[verification_id]

    def certification_record(
        self, certification_id: str, seq: int
    ) -> CertificationRecord:
        with self._lock:
            self._check_read_seq(seq)
            if certification_id not in self._certifications:
                raise UnknownRecordError(
                    f"unknown certification id: {certification_id!r}"
                )
            return self._certifications[certification_id]

    def verifications_for(
        self, subject_id: str, seq: int
    ) -> Tuple[VerificationRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._verifications[i]
                for i in self._subject_verifications.get(subject_id, [])
            )

    def certifications_for(
        self, verification_id: str, seq: int
    ) -> Tuple[CertificationRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._certifications[c]
                for c in self._verification_certifications.get(verification_id, [])
            )

    def subject_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._subject_verifications))

    def verification_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._verifications))

    def certification_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._certifications))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_subjects": len(self._subject_verifications),
                "n_verifications": len(self._verifications),
                "n_certifications": len(self._certifications),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_VERIFICATION_VERSION,
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
    """Self-check: exercise verify -> certify -> verify-report -> evaluate."""
    ledger = AIVerification()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.verify(
        "subject-1",
        1,
        check_kind="formal-proof",
        verdict="verified",
        severity=10,
    )
    assert rec.verify()
    crt = ledger.certify(rec.verification_id, 2, certification_kind="peer-review")
    assert crt.verify()
    rep = ledger.verify_report(rec.verification_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("subject-1", 4)
    assert ev.posture == "certified"
    ret = ledger.retire("subject-1", 5)
    assert ret.verify()
    print("ai-verification OK: verify, certify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
