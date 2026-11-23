"""AI privacy: privacy assessment/protection decision ledger, Simulated.

Research note: AI privacy is the field concerned with protecting personal
data and individual rights in AI systems - data minimization, consent,
purpose limitation, retention, anonymization, and cross-border transfer
governance. This module is the *decision ledger* for declared AI-privacy
assessments: which systems had which privacy assessments booked (over a
pinned privacy-risk vocabulary), what verdicts were declared against
them, what protections the host declared, and what privacy posture the
ledger derives - defensible bookkeeping, never proof that a system really
protects privacy.

This module owns the assess -> protect -> evaluate lifecycle:

* **assess()** - book one declared privacy assessment (minted ``asm-N``
  ids; pinned privacy-risk vocabulary over the common AI-privacy risk
  classes; pinned verdict vocabulary booked *as data*); the first
  assessment registers its system; raw personal data, data inventories,
  and material never enter records - digest pins only.
* **protect()** - book one declared protection against a booked
  assessment (minted ``prt-N`` ids; pinned protection-strategy vocabulary
  booked *as data*); repeatable chain; books the *declaration*, never
  the deployed control.
* **verify()** - **pure read**: re-derive one assessment/protection
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the assessment really happened.
* **evaluate()** - **pure read**: derive one system's privacy posture as
  data (``unassessed`` -> ``noncompliant`` -> ``at-risk`` ->
  ``mitigated`` -> ``compliant``) with verdict tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``privacy.py`` (if present) owns
privacy *mechanics* (redaction/consent toggles); ``ai_ethics.py`` owns
the per-system AI-ethics assessment ledger; ``ai_safety.py`` owns the
safety assessment/mitigation lifecycle; ``ai_governance.py`` owns the
governance-operations ledger - this module is the AI-privacy
assessment/protection decision ledger none of them own: declared
privacy assessments, declared protections, digest re-derivation, and
the ledger-rule posture that turns declared verdicts into a privacy
claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-privacy.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no systems, applies
no protections, and proves nothing about real privacy compliance. A
booked ``noncompliant`` verdict means "the host declared it", never
"the system violates privacy law"; a booked protection means "the host
declared it", never "the data is now safe". Personal data, PII,
biometrics, location traces, and raw assessment material never enter
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
AI_PRIVACY_VERSION = "ai-privacy.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-privacy.v1"

#: Pinned privacy-risk vocabulary (the AI-privacy risk classes assessed).
RISK_KINDS = (
    "data-minimization",
    "consent-management",
    "purpose-limitation",
    "data-retention",
    "anonymization",
    "access-control",
    "cross-border-transfer",
    "surveillance-risk",
)

#: Pinned assessment-verdict vocabulary (booked as data, never proof).
ASSESS_VERDICTS = (
    "compliant",
    "noncompliant",
    "at-risk",
    "inconclusive",
    "not-assessed",
)

#: Pinned protection-strategy vocabulary (booked as data, never proof).
PROTECTION_STRATEGIES = (
    "differential-privacy",
    "data-minimization",
    "encryption-at-rest",
    "access-tightening",
    "retention-shortening",
    "anonymization-upgrade",
    "consent-refresh",
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
    "noncompliant",
    "at-risk",
    "mitigated",
    "compliant",
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
    "protected",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "personal_data",
        "pii",
        "biometric",
        "biometrics",
        "face",
        "fingerprint",
        "location",
        "gps",
        "address",
        "email",
        "phone",
        "ssn",
        "id_number",
        "messages",
        "chat",
        "inbox",
        "contacts",
        "calendar",
        "photos",
        "health",
        "genetic",
        "voice",
        "keystroke",
        "browsing",
        "purchase",
        "financial",
        "payment",
        "transaction",
        "consent_record",
        "dsar",
        "deletion_request",
        "data_inventory",
        "schema_dump",
        "table",
        "column",
        "dataset",
        "sample",
        "record",
        "row",
        "field",
        "value",
        "payload",
        "prompt",
        "response",
        "transcript",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIPrivacyError(Exception):
    """Base class for all ai-privacy ledger errors."""


class BadSystemError(AIPrivacyError):
    pass


class UnknownSystemError(AIPrivacyError):
    pass


class RetiredSystemError(AIPrivacyError):
    pass


class BadRiskKindError(AIPrivacyError):
    pass


class BadVerdictError(AIPrivacyError):
    pass


class BadSeverityError(AIPrivacyError):
    pass


class BadDigestError(AIPrivacyError):
    pass


class BadReasonError(AIPrivacyError):
    pass


class UnknownAssessmentError(AIPrivacyError):
    pass


class UnknownProtectionError(AIPrivacyError):
    pass


class UnknownRecordError(AIPrivacyError):
    pass


class BadStrategyError(AIPrivacyError):
    pass


class SeqOrderError(AIPrivacyError):
    pass


class AuditKindError(AIPrivacyError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_risk_kind(value: Any) -> str:
    if value not in RISK_KINDS:
        raise BadRiskKindError(f"risk_kind must be one of {RISK_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in ASSESS_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {ASSESS_VERDICTS}")
    return value


def _check_strategy(value: Any) -> str:
    if value not in PROTECTION_STRATEGIES:
        raise BadStrategyError(f"strategy must be one of {PROTECTION_STRATEGIES}")
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
class AssessmentRecord:
    assessment_id: str
    system_id: str
    seq: int
    risk_kind: str
    verdict: str
    severity: int
    assessment_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _assess_payload(self), "ai-privacy.assess"
        )


@dataclass(frozen=True)
class ProtectionRecord:
    protection_id: str
    assessment_id: str
    system_id: str
    seq: int
    strategy: str
    protection_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _protect_payload(self), "ai-privacy.protect"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-privacy.retire"
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
            _verify_payload(self), "ai-privacy.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_assessments: int
    n_compliant: int
    n_noncompliant: int
    n_at_risk: int
    n_inconclusive: int
    n_not_assessed: int
    n_protected: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-privacy.evaluate"
        )


def _assess_payload(rec: "AssessmentRecord") -> Dict[str, Any]:
    return {
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "risk_kind": rec.risk_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "assessment_digest": rec.assessment_digest,
    }


def _protect_payload(rec: "ProtectionRecord") -> Dict[str, Any]:
    return {
        "protection_id": rec.protection_id,
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "strategy": rec.strategy,
        "protection_digest": rec.protection_digest,
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
        "n_compliant": rep.n_compliant,
        "n_noncompliant": rep.n_noncompliant,
        "n_at_risk": rep.n_at_risk,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_assessed": rep.n_not_assessed,
        "n_protected": rep.n_protected,
        "integrity_ok": rep.integrity_ok,
    }


def ai_privacy_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIPrivacyError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-privacy",
        "version": AI_PRIVACY_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIPrivacy:
    """AI-privacy assessment/protection decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and protections
    are booked as data - never proof that a system really protects
    privacy.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._protections: Dict[str, ProtectionRecord] = {}
        self._system_assessments: Dict[str, List[str]] = {}
        self._assessment_protections: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assessment_counter = 0
        self._protection_counter = 0
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
            row = ai_privacy_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-privacy",
                "version": AI_PRIVACY_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_privacy_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        risk_kind: str = "data-minimization",
        verdict: str = "not-assessed",
        severity: int = 0,
        assessment_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared privacy assessment (minted ``asm-N`` id).

        The first assessment on an id registers the system. Personal
        data, PII, and raw material never enter records - digest pins
        only. Fail-closed: failed mutations consume their seq and book
        an ``ai-privacy.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                risk_kind = _check_risk_kind(risk_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                assessment_digest = _check_digest(
                    assessment_digest, "assessment_digest"
                )
                self._require_live(system_id)
            except AIPrivacyError as exc:
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
                risk_kind=risk_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
                digest="",
            )
            digest = _digest_pin(_assess_payload(provisional), "ai-privacy.assess")
            rec = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                risk_kind=risk_kind,
                verdict=verdict,
                severity=severity,
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
                risk_kind=risk_kind,
                verdict=verdict,
                severity=severity,
            )
            return rec

    def protect(
        self,
        assessment_id: str,
        seq: int,
        strategy: str = "no-action",
        protection_digest: str = "",
    ) -> ProtectionRecord:
        """Book one declared protection against a booked assessment (minted ``prt-N`` id).

        Books the *declaration*, never the deployed control. Repeatable
        as a chain. Fail-closed: failed mutations consume their seq and
        book an ``ai-privacy.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                assessment_id = _check_id(assessment_id, "assessment_id")
                self._require_seq(seq)
                strategy = _check_strategy(strategy)
                protection_digest = _check_digest(
                    protection_digest, "protection_digest"
                )
                assessment = self._assessments.get(assessment_id)
                if assessment is None:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}"
                    )
                self._require_live(assessment.system_id)
            except AIPrivacyError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._protection_counter += 1
            protection_id = f"prt-{self._protection_counter}"
            provisional = ProtectionRecord(
                protection_id=protection_id,
                assessment_id=assessment_id,
                system_id=assessment.system_id,
                seq=seq,
                strategy=strategy,
                protection_digest=protection_digest,
                digest="",
            )
            digest = _digest_pin(_protect_payload(provisional), "ai-privacy.protect")
            rec = ProtectionRecord(
                protection_id=protection_id,
                assessment_id=assessment_id,
                system_id=assessment.system_id,
                seq=seq,
                strategy=strategy,
                protection_digest=protection_digest,
                digest=digest,
            )
            self._protections[protection_id] = rec
            self._assessment_protections.setdefault(assessment_id, []).append(
                protection_id
            )
            self._emit(
                "protected",
                seq,
                protection_id=protection_id,
                assessment_id=assessment_id,
                system_id=assessment.system_id,
                strategy=strategy,
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
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIPrivacyError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-privacy.retire")
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
            self._assessments[aid].verify()
            and all(
                self._protections[pid].verify()
                for pid in self._assessment_protections.get(aid, [])
            )
            for aid in self._system_assessments.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "compliant": 0,
            "noncompliant": 0,
            "at-risk": 0,
            "inconclusive": 0,
            "not-assessed": 0,
            "protected": 0,
        }
        ids = self._system_assessments.get(system_id, [])
        for aid in ids:
            rec = self._assessments[aid]
            tallies[rec.verdict] += 1
            if self._assessment_protections.get(aid):
                tallies["protected"] += 1
        if not ids:
            return "unassessed", tallies
        if any(
            self._assessments[aid].verdict == "noncompliant"
            and not self._assessment_protections.get(aid)
            for aid in ids
        ):
            return "noncompliant", tallies
        if tallies["at-risk"] or tallies["inconclusive"]:
            return "at-risk", tallies
        if tallies["noncompliant"]:
            return "mitigated", tallies
        if all(self._assessments[aid].verdict == "compliant" for aid in ids):
            return "compliant", tallies
        return "at-risk", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._assessments.get(record_id) or self._protections.get(record_id)
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
            digest = _digest_pin(_verify_payload(provisional), "ai-privacy.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's privacy posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_assessments:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(self._system_assessments[system_id]),
                n_compliant=tallies["compliant"],
                n_noncompliant=tallies["noncompliant"],
                n_at_risk=tallies["at-risk"],
                n_inconclusive=tallies["inconclusive"],
                n_not_assessed=tallies["not-assessed"],
                n_protected=tallies["protected"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-privacy.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(self._system_assessments[system_id]),
                n_compliant=tallies["compliant"],
                n_noncompliant=tallies["noncompliant"],
                n_at_risk=tallies["at-risk"],
                n_inconclusive=tallies["inconclusive"],
                n_not_assessed=tallies["not-assessed"],
                n_protected=tallies["protected"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) ------------------------------------------------

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._assessments.get(assessment_id)
            if rec is None:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}"
                )
            return rec

    def protection_record(self, protection_id: str, seq: int) -> ProtectionRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._protections.get(protection_id)
            if rec is None:
                raise UnknownProtectionError(
                    f"unknown protection: {protection_id!r}"
                )
            return rec

    def assessments_for(self, system_id: str, seq: int) -> Tuple[AssessmentRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._assessments[aid]
                for aid in self._system_assessments.get(system_id, [])
            )

    def protections_for(self, assessment_id: str, seq: int) -> Tuple[ProtectionRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._protections[pid]
                for pid in self._assessment_protections.get(assessment_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_assessments.keys()))

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._assessments.keys()))

    def protection_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._protections.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_assessments),
                "n_assessments": len(self._assessments),
                "n_protections": len(self._protections),
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
    """Self-check: exercise assess -> protect -> verify -> evaluate."""
    ledger = AIPrivacy()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.assess(
        "sys-1", 1, risk_kind="data-retention", verdict="noncompliant", severity=70
    )
    assert rec.verify()
    prt = ledger.protect(rec.assessment_id, 2, strategy="retention-shortening")
    assert prt.verify()
    rep = ledger.verify(rec.assessment_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "mitigated"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-privacy OK: assess, protect, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
