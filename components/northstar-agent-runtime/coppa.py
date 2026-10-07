"""COPPA: Children's Online Privacy Protection Act compliance decision ledger, Simulated.

Research note: the Children's Online Privacy Protection Act (15 U.S.C.
sections 6501-6508) requires operators of websites or online services
directed to children under 13 (or with actual knowledge they collect
personal information from children under 13) to obtain *verifiable
parental consent* before collecting, using, or disclosing that personal
information, to give parents access to and the right to delete it, and to
retain it only as long as reasonably necessary. What matters here is the
*decision ledger*: which services were assessed under what coverage
theory, which consent flows were declared and with what outcomes, and
which child-data items were declared deleted - defensible bookkeeping,
not proof of legal compliance.

This module owns the assess -> verify -> delete lifecycle:

* **assess()** - book one declared COPPA coverage assessment for a
  service/operator (pinned coverage theory, verifiable-parental-consent
  method vocabulary, data-minimization and retention declarations);
  verdicts are data, never proof of compliance.
* **verify()** - book one declared parental-consent verification outcome
  (minted ``con-N`` ids; pinned verdict vocabulary) against an assessed
  service.
* **delete()** - terminal declared deletion of a child-data item (pinned
  reason vocabulary); ids are never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``coppa.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module contacts no operator, screens no child's age,
collects no consent, and deletes no bytes. A booked
``consent-verified`` means "the host declared the consent flow was
verified", never "a parent actually consented". Child names, birthdates,
email addresses, addresses, and any raw personal information never
enter records or cross the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
COPPA_VERSION = "coppa.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.coppa.v1"

#: Pinned coverage-theory vocabulary (why COPPA applies to this service).
COVERAGES = (
    "child-directed",
    "actual-knowledge",
    "not-covered",
)

#: Pinned verifiable-parental-consent method vocabulary (FTC-approved
#: methods plus the absence of one, booked as data).
CONSENT_METHODS = (
    "email-plus",
    "credit-card",
    "signed-consent",
    "video-conference",
    "knowledge-based",
    "parent-dashboard",
    "none",
)

#: Pinned consent-verification verdict vocabulary.
VERDICTS = (
    "consent-verified",
    "consent-denied",
    "pending",
    "expired",
)

#: Pinned data-deletion reason vocabulary.
DELETION_REASONS = (
    "parent-request",
    "retention-expired",
    "consent-withdrawn",
    "service-closure",
    "manual",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assessed",
    "verified",
    "deleted",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "child",
        "child_id",
        "child_name",
        "name",
        "first_name",
        "last_name",
        "email",
        "email_address",
        "phone",
        "address",
        "birthdate",
        "dob",
        "date_of_birth",
        "parent",
        "parent_name",
        "parent_email",
        "guardian",
        "custodian",
        "personal_information",
        "pi",
        "data",
        "content",
        "text",
        "note",
        "notes",
        "detail",
        "details",
        "description",
        "payload",
        "raw",
        "secret",
        "key",
        "ssn",
        "id_number",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CoppaError(Exception):
    """Base error for COPPA ledger misuse."""


class BadIdError(CoppaError):
    """Malformed service, consent, or child-data id."""


class DuplicateServiceError(CoppaError):
    """Service already assessed."""


class UnknownServiceError(CoppaError):
    """Service not assessed."""


class BadCoverageError(CoppaError):
    """Unknown COPPA coverage theory."""


class BadMethodError(CoppaError):
    """Unknown verifiable-parental-consent method."""


class BadDigestError(CoppaError):
    """Malformed sha256: digest pin."""


class DuplicateConsentError(CoppaError):
    """Consent id already verified for this service."""


class UnknownConsentError(CoppaError):
    """Consent id not verified."""


class BadVerdictError(CoppaError):
    """Unknown consent-verification verdict."""


class DuplicateDataError(CoppaError):
    """Child-data id already booked for deletion."""


class RetiredDataError(CoppaError):
    """Child-data id already deleted; never recycled."""


class BadReasonError(CoppaError):
    """Unknown deletion reason."""


class SeqOrderError(CoppaError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(CoppaError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    service_id: str
    coverage: str
    consent_method: str
    data_minimized: bool
    retention_limited: bool
    practices_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "service_id": self.service_id,
            "coverage": self.coverage,
            "consent_method": self.consent_method,
            "data_minimized": self.data_minimized,
            "retention_limited": self.retention_limited,
            "practices_digest": self.practices_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "service_id": self.service_id,
                "coverage": self.coverage,
                "consent_method": self.consent_method,
                "data_minimized": self.data_minimized,
                "retention_limited": self.retention_limited,
                "practices_digest": self.practices_digest,
            }
        )


@dataclass(frozen=True)
class VerificationRecord:
    consent_id: str
    service_id: str
    verdict: str
    consent_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "consent_id": self.consent_id,
            "service_id": self.service_id,
            "verdict": self.verdict,
            "consent_digest": self.consent_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "consent_id": self.consent_id,
                "service_id": self.service_id,
                "verdict": self.verdict,
                "consent_digest": self.consent_digest,
            }
        )


@dataclass(frozen=True)
class DeletionRecord:
    child_data_id: str
    service_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "child_data_id": self.child_data_id,
            "service_id": self.service_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "child_data_id": self.child_data_id,
                "service_id": self.service_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class StatusReport:
    n_services: int
    n_consents: int
    n_deleted: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "n_services": self.n_services,
            "n_consents": self.n_consents,
            "n_deleted": self.n_deleted,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "n_services": self.n_services,
                "n_consents": self.n_consents,
                "n_deleted": self.n_deleted,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def coppa_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the COPPA ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class COPPA:
    """COPPA compliance decision ledger, Simulated.

    ``assess()`` / ``verify()`` / ``delete()`` mutate the ledger and
    consume caller seqs; views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._verifications: Dict[str, VerificationRecord] = {}
        self._deletions: Dict[str, DeletionRecord] = {}
        self._deleted: set = set()
        self._consent_seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = coppa_audit_event("rejected", seq,
                                    rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(coppa_audit_event(audit_kind, seq, **details))

    # -- assess ------------------------------------------------------------

    def assess(
        self,
        service_id: str,
        seq: int,
        coverage: str = "child-directed",
        consent_method: str = "email-plus",
        data_minimized: bool = True,
        retention_limited: bool = True,
        practices_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared COPPA coverage assessment for a service.

        Data practices travel as a ``sha256:`` digest pin only - raw
        practice descriptions never enter records. Verdicts are data,
        never proof of compliance.
        """
        with self._lock:
            try:
                self._claim(seq)
            except CoppaError:
                raise
            try:
                _require_id(service_id, "service_id")
                if coverage not in COVERAGES:
                    raise BadCoverageError(
                        f"coverage must be one of {COVERAGES}")
                if consent_method not in CONSENT_METHODS:
                    raise BadMethodError(
                        f"consent_method must be one of {CONSENT_METHODS}")
                if not isinstance(data_minimized, bool):
                    raise CoppaError("data_minimized must be a bool")
                if not isinstance(retention_limited, bool):
                    raise CoppaError("retention_limited must be a bool")
                if practices_digest:
                    _require_digest(practices_digest, "practices_digest")
                else:
                    practices_digest = "sha256:" + "00" * 32
                if service_id in self._assessments:
                    raise DuplicateServiceError(
                        f"service already assessed: {service_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "service_id": service_id,
                     "coverage": coverage, "consent_method": consent_method,
                     "data_minimized": data_minimized,
                     "retention_limited": retention_limited,
                     "practices_digest": practices_digest}
                )
                record = AssessmentRecord(
                    service_id=service_id, coverage=coverage,
                    consent_method=consent_method,
                    data_minimized=data_minimized,
                    retention_limited=retention_limited,
                    practices_digest=practices_digest, digest=digest,
                )
                self._assessments[service_id] = record
                self._emit(
                    "assessed", seq, service_id=service_id,
                    coverage=coverage, consent_method=consent_method,
                )
                return record
            except CoppaError:
                self._burn(seq, "assess")
                raise

    # -- verify ------------------------------------------------------------

    def verify(
        self,
        service_id: str,
        seq: int,
        verdict: str = "consent-verified",
        consent_digest: str = "",
    ) -> VerificationRecord:
        """Book one declared parental-consent verification outcome.

        The consent id is minted (``con-N``); consent material travels as
        a digest pin only. The verdict is data, never proof of real
        parental consent.
        """
        with self._lock:
            try:
                self._claim(seq)
            except CoppaError:
                raise
            try:
                _require_id(service_id, "service_id")
                if service_id not in self._assessments:
                    raise UnknownServiceError(
                        f"unknown service: {service_id!r}")
                if verdict not in VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {VERDICTS}")
                if consent_digest:
                    _require_digest(consent_digest, "consent_digest")
                else:
                    consent_digest = "sha256:" + "00" * 32
                self._consent_seq += 1
                consent_id = f"con-{self._consent_seq}"
                if consent_id in self._verifications:
                    raise DuplicateConsentError(
                        f"consent already verified: {consent_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "consent_id": consent_id,
                     "service_id": service_id, "verdict": verdict,
                     "consent_digest": consent_digest}
                )
                record = VerificationRecord(
                    consent_id=consent_id, service_id=service_id,
                    verdict=verdict, consent_digest=consent_digest,
                    digest=digest,
                )
                self._verifications[consent_id] = record
                self._emit(
                    "verified", seq, consent_id=consent_id,
                    service_id=service_id, verdict=verdict,
                )
                return record
            except CoppaError:
                self._burn(seq, "verify")
                raise

    # -- delete ------------------------------------------------------------

    def delete(
        self, child_data_id: str, service_id: str, seq: int,
        reason: str = "parent-request",
    ) -> DeletionRecord:
        """Terminal: book a declared deletion of a child-data item.

        The id is never recycled. Books the *declaration*, never proof
        that bytes were erased.
        """
        with self._lock:
            try:
                self._claim(seq)
            except CoppaError:
                raise
            try:
                _require_id(child_data_id, "child_data_id")
                _require_id(service_id, "service_id")
                if service_id not in self._assessments:
                    raise UnknownServiceError(
                        f"unknown service: {service_id!r}")
                if reason not in DELETION_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {DELETION_REASONS}")
                if child_data_id in self._deleted:
                    raise RetiredDataError(
                        f"child data id deleted, never recycled: "
                        f"{child_data_id!r}")
                if child_data_id in self._deletions:
                    raise DuplicateDataError(
                        f"child data already booked: {child_data_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN,
                     "child_data_id": child_data_id,
                     "service_id": service_id, "reason": reason}
                )
                record = DeletionRecord(
                    child_data_id=child_data_id, service_id=service_id,
                    reason=reason, digest=digest,
                )
                self._deletions[child_data_id] = record
                self._deleted.add(child_data_id)
                self._emit(
                    "deleted", seq, child_data_id=child_data_id,
                    service_id=service_id, reason=reason,
                )
                return record
            except CoppaError:
                self._burn(seq, "delete")
                raise

    # -- views (pure reads) -------------------------------------------------

    def assessment_record(self, seq: int, service_id: str) -> AssessmentRecord:
        """Pure read: one assessment record."""
        with self._lock:
            self._require_read_seq(seq)
            record = self._assessments.get(service_id)
            if record is None:
                raise UnknownServiceError(f"unknown service: {service_id!r}")
            return record

    def verification_record(self, seq: int, consent_id: str) -> VerificationRecord:
        """Pure read: one verification record."""
        with self._lock:
            self._require_read_seq(seq)
            record = self._verifications.get(consent_id)
            if record is None:
                raise UnknownConsentError(
                    f"unknown consent: {consent_id!r}")
            return record

    def service_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: assessed service ids, sorted."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._assessments))

    def consent_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: minted consent ids, sorted."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._verifications))

    def deleted_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: deleted child-data ids, sorted."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._deleted))

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: audit rows, in order."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(dict(row) for row in self._audit)

    def _require_read_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("read seq must be a non-negative int")

    def status(self, seq: int) -> StatusReport:
        """Pure read: ledger tallies and digest-pinned integrity as data."""
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("read seq must be a non-negative int")
            integrity_ok = True
            for record in self._assessments.values():
                if not record.verify():
                    integrity_ok = False
            for record in self._verifications.values():
                if not record.verify():
                    integrity_ok = False
            for record in self._deletions.values():
                if not record.verify():
                    integrity_ok = False
            n_services = len(self._assessments)
            n_consents = len(self._verifications)
            n_deleted = len(self._deletions)
            digest = _digest_pin(
                {"schema": SCHEMA_PIN, "n_services": n_services,
                 "n_consents": n_consents, "n_deleted": n_deleted,
                 "integrity_ok": integrity_ok}
            )
            return StatusReport(
                n_services=n_services, n_consents=n_consents,
                n_deleted=n_deleted, integrity_ok=integrity_ok,
                digest=digest,
            )

    def stats(self, seq: int) -> Dict[str, int]:
        """Pure read: small numeric summary of the ledger."""
        with self._lock:
            self._require_read_seq(seq)
            return {
                "n_services": len(self._assessments),
                "n_consents": len(self._verifications),
                "n_deleted": len(self._deletions),
                "n_audit_rows": len(self._audit),
            }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """COPPA self-check: assess, verify, delete, pins, audit."""
    ledger = COPPA()
    ledger.assess("svc-1", 1, coverage="child-directed",
                  consent_method="email-plus")
    ledger.verify("svc-1", 2, verdict="consent-verified")
    ledger.delete("child-1", "svc-1", 3, reason="parent-request")
    report = ledger.status(3)
    assert report.verify()
    assert report.n_services == 1
    assert report.n_consents == 1
    assert report.n_deleted == 1
    print("coppa OK: assess, verify, delete, pins, audit")


if __name__ == "__main__":
    main()
