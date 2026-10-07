"""ISO 27001 certification: ISMS certification-lifecycle ledger, Simulated.

Research note: ISO/IEC 27001 certification is the auditable outcome of an
information security management system (ISMS). A certification body (CB)
runs a two-stage audit - stage 1 (documentation readiness) and stage 2
(implementation effectiveness) - and, when stage 2 closes with no blocking
findings, issues a certificate that is valid for a three-year cycle with
mandatory surveillance audits in years 1 and 2, followed by a
re-certification audit. What matters here is the *decision ledger*: which
assessments were declared, which stage-2 outcomes the host booked, which
certifications were granted, which surveillance years were booked, and
which certificates were withdrawn - defensible bookkeeping, not proof of
conformity.

This module is the *certification decision* layer, deliberately distinct
from its siblings:

- ``compliance.py`` - generic compliance framework ledger (framework ->
  control checks -> remediation -> attestation).
- ``audit_management.py`` - audit *engagement* management (who audits what
  under which standard).
- ``grc.py`` - governance/risk/compliance workflow ledger.
- ``risk_management.py`` - risk register and treatment decisions.

This module owns the assess -> certify -> surveil -> withdraw lifecycle:

* **assess()** - declare one certification assessment for an organization
  (stage-1 / stage-2; declared outcome vocabulary ``pass`` /
  ``minor-nc`` / ``major-nc`` / ``fail`` booked as data, never proof of
  real conformity). Scope and assessor identities travel as ``sha256:``
  digest pins only - raw evidence and names never enter records.
* **certify()** - declare certification granted. Fail-closed: requires a
  booked stage-2 assessment with outcome ``pass`` for the same
  organization; refuses if already certified or withdrawn.
* **surveil()** - book one declared surveillance audit (year 1 / year 2
  of the three-year cycle) against a live certificate; declared outcome
  vocabulary booked as data.
* **withdraw()** - terminal withdrawal of a certificate; withdrawn org ids
  are never recycled.
* **status()** - pure read view: certification posture per organization
  (``certified`` / ``not-certified`` / ``withdrawn`` / ``unknown``) as
  data, digest-pinned with ``verify()``.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``iso27001.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module performs no audit, inspects no ISMS, and
certifies nothing. A booked ``pass`` means "the host declared a pass",
never "the organization conforms". A booked ``certified`` means the
ledger's rules were satisfied, never that the certificate is genuine or
would survive a real certification-body review.
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
ISO27001_VERSION = "iso27001.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.iso27001.v1"

#: Pinned assessment-stage vocabulary (ISO 27001 certification audits).
STAGES = (
    "stage-1",
    "stage-2",
)

#: Pinned assessment-outcome vocabulary (host-declared, booked as data).
ASSESSMENT_OUTCOMES = (
    "pass",
    "minor-nc",
    "major-nc",
    "fail",
)

#: Pinned surveillance years of the three-year certification cycle.
SURVEILLANCE_YEARS = (1, 2)

#: Pinned surveillance-outcome vocabulary (host-declared, booked as data).
SURVEILLANCE_OUTCOMES = (
    "maintain",
    "minor-nc",
    "major-nc",
    "suspension-recommended",
)

#: Pinned withdrawal-reason vocabulary (why the certificate was pulled).
WITHDRAW_REASONS = (
    "manual",
    "major-nc-unresolved",
    "scope-withdrawn",
    "fraud",
    "certificate-expired",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assessed",
    "certified",
    "surveiled",
    "withdrawn",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "org",
        "org_name",
        "organization",
        "organization_name",
        "scope",
        "scope_detail",
        "scope_description",
        "assessor",
        "assessor_name",
        "auditor",
        "auditor_name",
        "evidence",
        "finding",
        "findings",
        "nonconformity",
        "report",
        "basis",
        "name",
        "note",
        "notes",
        "text",
        "content",
        "payload",
        "raw",
        "data",
        "secret",
        "private_key",
        "key",
        "signature",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ISO27001Error(Exception):
    """Base error for the ISO 27001 certification-ledger misuse."""


class BadOrgError(ISO27001Error):
    """Malformed organization id."""


class BadIdError(ISO27001Error):
    """Malformed assessment id."""


class BadStageError(ISO27001Error):
    """Unknown assessment stage."""


class BadOutcomeError(ISO27001Error):
    """Unknown assessment or surveillance outcome."""


class BadYearError(ISO27001Error):
    """Surveillance year not in the pinned cycle (1, 2)."""


class BadDigestError(ISO27001Error):
    """Malformed sha256: digest pin."""


class BadReasonError(ISO27001Error):
    """Unknown withdrawal reason."""


class DuplicateAssessmentError(ISO27001Error):
    """Assessment id already booked for this organization."""


class DuplicateSurveillanceError(ISO27001Error):
    """Surveillance already booked for this organization and year."""


class UnknownOrgError(ISO27001Error):
    """No assessment ever booked for this organization."""


class UnknownAssessmentError(ISO27001Error):
    """Assessment id not booked for this organization."""


class NotEligibleError(ISO27001Error):
    """No booked stage-2 assessment with outcome 'pass' to certify on."""


class AlreadyCertifiedError(ISO27001Error):
    """Organization already holds a live certificate."""


class NotCertifiedError(ISO27001Error):
    """No live certificate for this organization (surveil refused)."""


class WithdrawnError(ISO27001Error):
    """Organization withdrawn; id never recycled."""


class SeqOrderError(ISO27001Error):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(ISO27001Error):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str, error: type) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise error(f"{field_name} must be a non-empty str <= 128 chars")
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


_DEFAULT_PIN = "sha256:" + "00" * 32


def _pin_or_default(pin: str, field_name: str) -> str:
    if not pin:
        return _DEFAULT_PIN
    return _require_digest(pin, field_name)


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    org_id: str
    assessment_id: str
    stage: str
    outcome: str
    scope_digest: str
    assessor_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "org_id": self.org_id,
            "assessment_id": self.assessment_id,
            "stage": self.stage,
            "outcome": self.outcome,
            "scope_digest": self.scope_digest,
            "assessor_digest": self.assessor_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "org_id": self.org_id,
                "assessment_id": self.assessment_id,
                "stage": self.stage,
                "outcome": self.outcome,
                "scope_digest": self.scope_digest,
                "assessor_digest": self.assessor_digest,
            }
        )


@dataclass(frozen=True)
class CertificationRecord:
    org_id: str
    basis_assessment_id: str
    assessor_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "org_id": self.org_id,
            "basis_assessment_id": self.basis_assessment_id,
            "assessor_digest": self.assessor_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "org_id": self.org_id,
                "basis_assessment_id": self.basis_assessment_id,
                "assessor_digest": self.assessor_digest,
            }
        )


@dataclass(frozen=True)
class SurveillanceRecord:
    surveillance_id: str
    org_id: str
    year: int
    outcome: str
    assessor_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "surveillance_id": self.surveillance_id,
            "org_id": self.org_id,
            "year": self.year,
            "outcome": self.outcome,
            "assessor_digest": self.assessor_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "surveillance_id": self.surveillance_id,
                "org_id": self.org_id,
                "year": self.year,
                "outcome": self.outcome,
                "assessor_digest": self.assessor_digest,
            }
        )


@dataclass(frozen=True)
class WithdrawalRecord:
    org_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "org_id": self.org_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "org_id": self.org_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class CertificationStatus:
    org_id: str
    posture: str
    n_assessments: int
    has_passing_stage2: bool
    n_surveillance: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "org_id": self.org_id,
            "posture": self.posture,
            "n_assessments": self.n_assessments,
            "has_passing_stage2": self.has_passing_stage2,
            "n_surveillance": self.n_surveillance,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "org_id": self.org_id,
                "posture": self.posture,
                "n_assessments": self.n_assessments,
                "has_passing_stage2": self.has_passing_stage2,
                "n_surveillance": self.n_surveillance,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def iso27001_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the ISO 27001 ledger."""
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


class ISO27001:
    """ISO 27001 certification-lifecycle decision ledger, Simulated.

    ``assess()`` / ``certify()`` / ``surveil()`` / ``withdraw()`` mutate
    the ledger and consume caller seqs; ``status()`` and all views are
    pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._assessments: Dict[Tuple[str, str], AssessmentRecord] = {}
        self._certs: Dict[str, CertificationRecord] = {}
        self._surv: Dict[Tuple[str, int], SurveillanceRecord] = {}
        self._withdrawn: set = set()
        self._withdrawals: Dict[str, WithdrawalRecord] = {}
        self._svl_counter = 0
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
            row = iso27001_audit_event("rejected", seq,
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
        self._audit.append(iso27001_audit_event(audit_kind, seq, **details))

    def _live_org(self, org_id: str) -> None:
        """Fail-closed: org must not be withdrawn."""
        if org_id in self._withdrawn:
            raise WithdrawnError(
                f"org withdrawn, id never recycled: {org_id!r}")

    def _known_org(self, org_id: str) -> None:
        self._live_org(org_id)
        if not any(key[0] == org_id for key in self._assessments):
            raise UnknownOrgError(f"unknown org: {org_id!r}")

    # -- assess ---------------------------------------------------------------

    def assess(
        self,
        org_id: str,
        assessment_id: str,
        stage: str,
        seq: int,
        outcome: str = "pass",
        scope_digest: str = "",
        assessor_digest: str = "",
    ) -> AssessmentRecord:
        """Declare one certification assessment for an organization.

        The declared ``outcome`` is booked as data (GIGO), never proof of
        real conformity. Scope and assessor identities travel as
        ``sha256:`` digest pins only.
        """
        with self._lock:
            try:
                self._claim(seq)
            except ISO27001Error:
                raise
            try:
                _require_id(org_id, "org_id", BadOrgError)
                _require_id(assessment_id, "assessment_id", BadIdError)
                self._live_org(org_id)
                if stage not in STAGES:
                    raise BadStageError(f"stage must be one of {STAGES}")
                if outcome not in ASSESSMENT_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {ASSESSMENT_OUTCOMES}")
                scope_digest = _pin_or_default(scope_digest, "scope_digest")
                assessor_digest = _pin_or_default(
                    assessor_digest, "assessor_digest")
                if (org_id, assessment_id) in self._assessments:
                    raise DuplicateAssessmentError(
                        f"assessment already booked: {assessment_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "org_id": org_id,
                        "assessment_id": assessment_id,
                        "stage": stage,
                        "outcome": outcome,
                        "scope_digest": scope_digest,
                        "assessor_digest": assessor_digest,
                    }
                )
                record = AssessmentRecord(
                    org_id=org_id, assessment_id=assessment_id, stage=stage,
                    outcome=outcome, scope_digest=scope_digest,
                    assessor_digest=assessor_digest, digest=digest,
                )
                self._assessments[(org_id, assessment_id)] = record
                self._emit(
                    "assessed", seq, org_id=org_id,
                    assessment_id=assessment_id, stage=stage, outcome=outcome,
                )
                return record
            except ISO27001Error:
                self._burn(seq, "assess")
                raise

    # -- certify ----------------------------------------------------------------

    def certify(
        self, org_id: str, seq: int, assessor_digest: str = ""
    ) -> CertificationRecord:
        """Declare certification granted for an organization.

        Fail-closed: requires a booked stage-2 assessment with outcome
        ``pass`` for the same org; refuses if already certified or
        withdrawn. The basis assessment id is booked in the record.
        """
        with self._lock:
            try:
                self._claim(seq)
            except ISO27001Error:
                raise
            try:
                _require_id(org_id, "org_id", BadOrgError)
                self._known_org(org_id)
                if org_id in self._certs:
                    raise AlreadyCertifiedError(
                        f"org already certified: {org_id!r}")
                assessor_digest = _pin_or_default(
                    assessor_digest, "assessor_digest")
                basis = None
                for (oid, aid), record in self._assessments.items():
                    if (oid == org_id and record.stage == "stage-2"
                            and record.outcome == "pass"):
                        basis = aid
                if basis is None:
                    raise NotEligibleError(
                        f"no booked stage-2 'pass' for org: {org_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "org_id": org_id,
                        "basis_assessment_id": basis,
                        "assessor_digest": assessor_digest,
                    }
                )
                record = CertificationRecord(
                    org_id=org_id, basis_assessment_id=basis,
                    assessor_digest=assessor_digest, digest=digest,
                )
                self._certs[org_id] = record
                self._emit(
                    "certified", seq, org_id=org_id,
                    basis_assessment_id=basis,
                )
                return record
            except ISO27001Error:
                self._burn(seq, "certify")
                raise

    # -- surveil ------------------------------------------------------------------

    def surveil(
        self,
        org_id: str,
        year: int,
        seq: int,
        outcome: str = "maintain",
        assessor_digest: str = "",
    ) -> SurveillanceRecord:
        """Book one declared surveillance audit (year 1 / year 2).

        Requires a live certificate. Declared ``outcome`` is booked as
        data, never proof of a real audit visit.
        """
        with self._lock:
            try:
                self._claim(seq)
            except ISO27001Error:
                raise
            try:
                _require_id(org_id, "org_id", BadOrgError)
                self._live_org(org_id)
                if isinstance(year, bool) or not isinstance(year, int):
                    raise BadYearError("year must be an int")
                if year not in SURVEILLANCE_YEARS:
                    raise BadYearError(
                        f"year must be one of {SURVEILLANCE_YEARS}")
                if outcome not in SURVEILLANCE_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {SURVEILLANCE_OUTCOMES}")
                if org_id not in self._certs:
                    raise NotCertifiedError(
                        f"no live certificate for org: {org_id!r}")
                if (org_id, year) in self._surv:
                    raise DuplicateSurveillanceError(
                        f"surveillance already booked: year {year}")
                assessor_digest = _pin_or_default(
                    assessor_digest, "assessor_digest")
                self._svl_counter += 1
                surveillance_id = f"svl-{self._svl_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "surveillance_id": surveillance_id,
                        "org_id": org_id,
                        "year": year,
                        "outcome": outcome,
                        "assessor_digest": assessor_digest,
                    }
                )
                record = SurveillanceRecord(
                    surveillance_id=surveillance_id, org_id=org_id,
                    year=year, outcome=outcome,
                    assessor_digest=assessor_digest, digest=digest,
                )
                self._surv[(org_id, year)] = record
                self._emit(
                    "surveiled", seq, org_id=org_id, year=year,
                    outcome=outcome, surveillance_id=surveillance_id,
                )
                return record
            except ISO27001Error:
                self._burn(seq, "surveil")
                raise

    # -- withdraw -------------------------------------------------------------------

    def withdraw(
        self, org_id: str, seq: int, reason: str = "manual"
    ) -> WithdrawalRecord:
        """Terminal: withdraw an organization's certificate.

        The org id is never recycled; later assess/certify/surveil on it
        all refuse fail-closed. Reads still work.
        """
        with self._lock:
            try:
                self._claim(seq)
            except ISO27001Error:
                raise
            try:
                _require_id(org_id, "org_id", BadOrgError)
                self._known_org(org_id)
                if reason not in WITHDRAW_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {WITHDRAW_REASONS}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "org_id": org_id,
                        "reason": reason,
                    }
                )
                record = WithdrawalRecord(
                    org_id=org_id, reason=reason, digest=digest)
                self._withdrawals[org_id] = record
                self._withdrawn.add(org_id)
                self._emit("withdrawn", seq, org_id=org_id, reason=reason)
                return record
            except ISO27001Error:
                self._burn(seq, "withdraw")
                raise

    # -- status (pure read) -------------------------------------------------------

    def _posture(self, org_id: str) -> str:
        if org_id in self._withdrawn:
            return "withdrawn"
        if org_id in self._certs:
            return "certified"
        if any(key[0] == org_id for key in self._assessments):
            return "not-certified"
        return "unknown"

    def _status_for(self, org_id: str) -> CertificationStatus:
        assessments = [
            record for (oid, _), record in self._assessments.items()
            if oid == org_id
        ]
        n_surv = sum(1 for (oid, _) in self._surv if oid == org_id)
        passing_stage2 = any(
            r.stage == "stage-2" and r.outcome == "pass" for r in assessments
        )
        integrity_ok = all(r.verify() for r in assessments)
        cert = self._certs.get(org_id)
        if cert is not None and not cert.verify():
            integrity_ok = False
        wd = self._withdrawals.get(org_id)
        if wd is not None and not wd.verify():
            integrity_ok = False
        for (oid, _), record in self._surv.items():
            if oid == org_id and not record.verify():
                integrity_ok = False
        posture = self._posture(org_id)
        digest = _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "org_id": org_id,
                "posture": posture,
                "n_assessments": len(assessments),
                "has_passing_stage2": passing_stage2,
                "n_surveillance": n_surv,
                "integrity_ok": integrity_ok,
            }
        )
        return CertificationStatus(
            org_id=org_id, posture=posture,
            n_assessments=len(assessments),
            has_passing_stage2=passing_stage2,
            n_surveillance=n_surv, integrity_ok=integrity_ok, digest=digest,
        )

    def status(self, seq: int, org_id: str = "") -> CertificationStatus:
        """Pure read: certification posture as data, digest-pinned.

        With ``org_id`` set, the report scopes to that one org (unknown
        ids report ``unknown`` posture as data, never raised); without
        it, the report aggregates over the whole ledger.
        """
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("status seq must be a non-negative int")
            if org_id:
                return self._status_for(org_id)
            orgs = sorted({key[0] for key in self._assessments})
            n_surv = len(self._surv)
            passing = any(
                r.stage == "stage-2" and r.outcome == "pass"
                for r in self._assessments.values()
            )
            integrity_ok = all(
                r.verify() for r in self._assessments.values()
            )
            integrity_ok = integrity_ok and all(
                r.verify() for r in self._certs.values()
            )
            integrity_ok = integrity_ok and all(
                r.verify() for r in self._surv.values()
            )
            integrity_ok = integrity_ok and all(
                r.verify() for r in self._withdrawals.values()
            )
            posture = f"{len(orgs)}-orgs"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "org_id": "",
                    "posture": posture,
                    "n_assessments": len(self._assessments),
                    "has_passing_stage2": passing,
                    "n_surveillance": n_surv,
                    "integrity_ok": integrity_ok,
                }
            )
            return CertificationStatus(
                org_id="", posture=posture,
                n_assessments=len(self._assessments),
                has_passing_stage2=passing,
                n_surveillance=n_surv, integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def assessment_record(
        self, org_id: str, assessment_id: str, seq: int
    ) -> AssessmentRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._assessments.get((org_id, assessment_id))
            if record is None:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}")
            return record

    def assessment_ids(self, seq: int) -> Tuple[Tuple[str, str], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._assessments))

    def assessments_for(
        self, org_id: str, seq: int
    ) -> Tuple[AssessmentRecord, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(
                self._assessments[key]
                for key in sorted(self._assessments)
                if key[0] == org_id
            )

    def certification_record(
        self, org_id: str, seq: int
    ) -> CertificationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._certs.get(org_id)
            if record is None:
                raise NotCertifiedError(
                    f"no live certificate for org: {org_id!r}")
            return record

    def surveillance_record(
        self, org_id: str, year: int, seq: int
    ) -> SurveillanceRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._surv.get((org_id, year))
            if record is None:
                raise UnknownAssessmentError(
                    f"no surveillance booked: {org_id!r} year {year}")
            return record

    def surveillances_for(
        self, org_id: str, seq: int
    ) -> Tuple[SurveillanceRecord, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(
                self._surv[key] for key in sorted(self._surv)
                if key[0] == org_id
            )

    def org_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted({key[0] for key in self._assessments}))

    def certified_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._certs))

    def withdrawn_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._withdrawn))

    def is_certified(self, org_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq_ok(seq)
            return org_id in self._certs and org_id not in self._withdrawn

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "orgs": len({key[0] for key in self._assessments}),
                "assessments": len(self._assessments),
                "certified": len(self._certs),
                "withdrawn": len(self._withdrawn),
                "surveillance": len(self._surv),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)


def main() -> None:
    iso = ISO27001()
    a1 = iso.assess("org-1", "a1", "stage-1", 1, outcome="pass")
    assert a1.verify()
    a2 = iso.assess("org-1", "a2", "stage-2", 2, outcome="pass")
    assert a2.verify()
    cert = iso.certify("org-1", 3)
    assert cert.verify()
    assert cert.basis_assessment_id == "a2"
    assert iso.is_certified("org-1", 0)
    s1 = iso.surveil("org-1", 1, 4, outcome="maintain")
    assert s1.verify() and s1.surveillance_id == "svl-1"
    st = iso.status(0, "org-1")
    assert st.verify()
    assert st.posture == "certified"
    assert st.n_assessments == 2 and st.n_surveillance == 1
    wd = iso.withdraw("org-1", 5, reason="manual")
    assert wd.verify()
    st2 = iso.status(0, "org-1")
    assert st2.posture == "withdrawn"
    assert not iso.is_certified("org-1", 0)
    print("iso27001 OK: assess, certify, surveil, withdraw, pins")


if __name__ == "__main__":
    main()
