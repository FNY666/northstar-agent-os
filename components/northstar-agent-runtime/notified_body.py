"""Notified-body conformity-assessment ledger, Simulated.

Research note: in EU product legislation (medical devices, machinery, and
now the AI Act's high-risk systems path), a *notified body* is an
independent conformity-assessment body designated by a member state to
assess a product against the applicable directives or regulations. The
assessment runs under pinned conformity-assessment *modules* - EU type
examination (module B), quality assurance of the production process
(module D), product verification (module F), unit verification (module
G), full quality assurance with design examination (module H1) - and,
when the assessment closes with no blocking findings, the notified body
grants a certificate that stays valid for a pinned cycle with mandatory
surveillance, and can withdraw it at any time. What matters here is the
*decision ledger*: which notified body declared which assessments, which
outcomes the host booked, which certificates were granted, which
surveillance years were booked, and which certificates were withdrawn -
defensible bookkeeping, not proof of conformity.

This module is the *notified-body assessment* layer, deliberately
distinct from its siblings:

- ``ai_act.py`` - AI Act classification / conformance decisions.
- ``iso27001.py`` - ISMS certification-lifecycle ledger (stage audits).
- ``compliance.py`` - generic compliance framework ledger (framework ->
  control checks -> remediation -> attestation).
- ``audit_management.py`` - audit *engagement* management (who audits
  what under which standard).
- ``grc.py`` - governance/risk/compliance workflow ledger.

This module owns the assess -> certify -> surveil -> withdraw lifecycle:

* **assess()** - declare one conformity assessment run by a notified
  body for a client (pinned module vocabulary; declared outcome
  vocabulary ``pass`` / ``minor-nc`` / ``major-nc`` / ``fail`` booked as
  data, never proof of real conformity). Client/product identity and
  scope travel as ``sha256:`` digest pins only - raw names and evidence
  never enter records.
* **certify()** - declare a certificate granted. Fail-closed: requires
  a booked assessment with outcome ``pass`` for the same client; refuses
  if already certified or withdrawn.
* **surveil()** - book one declared surveillance audit (years 1..4 of
  the certificate cycle) against a live certificate; declared outcome
  vocabulary booked as data.
* **withdraw()** - terminal withdrawal of a certificate; withdrawn
  client ids are never recycled.
* **status()** - pure read view: certification posture per client
  (``certified`` / ``not-certified`` / ``withdrawn`` / ``unknown``) as
  data, digest-pinned with ``verify()``.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``notified-body.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no laboratory, inspects no product, and
certifies nothing. A booked ``pass`` means "the host declared a pass",
never "the product conforms". A booked ``certified`` means the ledger's
rules were satisfied, never that a real notified body issued a genuine
certificate.
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
NOTIFIED_BODY_VERSION = "notified-body.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.notified-body.v1"

#: Pinned conformity-assessment module vocabulary (EU-style module lettering).
MODULES = (
    "module-a",
    "module-b",
    "module-d",
    "module-f",
    "module-g",
    "module-h1",
)

#: Pinned assessment-outcome vocabulary (host-declared, booked as data).
ASSESSMENT_OUTCOMES = (
    "pass",
    "minor-nc",
    "major-nc",
    "fail",
)

#: Pinned certificate-validity years accepted at grant time.
VALIDITY_YEARS = (1, 2, 3, 4, 5)

#: Pinned surveillance years of the certificate cycle.
SURVEILLANCE_YEARS = (1, 2, 3, 4)

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
        "body",
        "body_id",
        "body_name",
        "client",
        "client_id",
        "client_name",
        "product",
        "product_id",
        "product_name",
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


class NotifiedBodyError(Exception):
    """Base error for notified-body ledger misuse."""


class BadBodyError(NotifiedBodyError):
    """Malformed notified-body id."""


class BadClientError(NotifiedBodyError):
    """Malformed client id."""


class BadIdError(NotifiedBodyError):
    """Malformed assessment / certificate / surveillance id."""


class BadModuleError(NotifiedBodyError):
    """Unknown conformity-assessment module."""


class BadOutcomeError(NotifiedBodyError):
    """Unknown assessment or surveillance outcome."""


class BadYearError(NotifiedBodyError):
    """Surveillance year not in the pinned cycle (1..4)."""


class BadValidityError(NotifiedBodyError):
    """Certificate validity not in the pinned vocabulary (1..5 years)."""


class BadDigestError(NotifiedBodyError):
    """Malformed sha256: digest pin."""


class BadReasonError(NotifiedBodyError):
    """Unknown withdrawal reason."""


class DuplicateAssessmentError(NotifiedBodyError):
    """Assessment id already booked for this client."""


class DuplicateSurveillanceError(NotifiedBodyError):
    """Surveillance already booked for this client and year."""


class UnknownClientError(NotifiedBodyError):
    """No assessment ever booked for this client."""


class UnknownAssessmentError(NotifiedBodyError):
    """Assessment id not booked for this client."""


class NotEligibleError(NotifiedBodyError):
    """No booked 'pass' assessment to certify on."""


class AlreadyCertifiedError(NotifiedBodyError):
    """Client already holds a live certificate."""


class NotCertifiedError(NotifiedBodyError):
    """No live certificate for this client (surveil refused)."""


class WithdrawnError(NotifiedBodyError):
    """Client withdrawn; id never recycled."""


class SeqOrderError(NotifiedBodyError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(NotifiedBodyError):
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
    body_id: str
    client_id: str
    assessment_id: str
    module: str
    outcome: str
    scope_digest: str
    assessor_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "body_id": self.body_id,
            "client_id": self.client_id,
            "assessment_id": self.assessment_id,
            "module": self.module,
            "outcome": self.outcome,
            "scope_digest": self.scope_digest,
            "assessor_digest": self.assessor_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "body_id": self.body_id,
                "client_id": self.client_id,
                "assessment_id": self.assessment_id,
                "module": self.module,
                "outcome": self.outcome,
                "scope_digest": self.scope_digest,
                "assessor_digest": self.assessor_digest,
            }
        )


@dataclass(frozen=True)
class CertificationRecord:
    client_id: str
    certificate_id: str
    basis_assessment_id: str
    validity_years: int
    assessor_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "client_id": self.client_id,
            "certificate_id": self.certificate_id,
            "basis_assessment_id": self.basis_assessment_id,
            "validity_years": self.validity_years,
            "assessor_digest": self.assessor_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "client_id": self.client_id,
                "certificate_id": self.certificate_id,
                "basis_assessment_id": self.basis_assessment_id,
                "validity_years": self.validity_years,
                "assessor_digest": self.assessor_digest,
            }
        )


@dataclass(frozen=True)
class SurveillanceRecord:
    surveillance_id: str
    client_id: str
    year: int
    outcome: str
    assessor_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "surveillance_id": self.surveillance_id,
            "client_id": self.client_id,
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
                "client_id": self.client_id,
                "year": self.year,
                "outcome": self.outcome,
                "assessor_digest": self.assessor_digest,
            }
        )


@dataclass(frozen=True)
class WithdrawalRecord:
    client_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "client_id": self.client_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "client_id": self.client_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class CertificateStatus:
    client_id: str
    posture: str
    n_assessments: int
    has_passing_assessment: bool
    n_surveillance: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "client_id": self.client_id,
            "posture": self.posture,
            "n_assessments": self.n_assessments,
            "has_passing_assessment": self.has_passing_assessment,
            "n_surveillance": self.n_surveillance,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "client_id": self.client_id,
                "posture": self.posture,
                "n_assessments": self.n_assessments,
                "has_passing_assessment": self.has_passing_assessment,
                "n_surveillance": self.n_surveillance,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def notified_body_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the notified-body ledger."""
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


class NotifiedBody:
    """Notified-body conformity-assessment decision ledger, Simulated.

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
        self._cert_counter = 0
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

    def _view_seq(self, seq: int) -> int:
        """Shape-validate a read-view seq: never consumed, never ordered."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = notified_body_audit_event("rejected", seq,
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
        self._audit.append(
            notified_body_audit_event(audit_kind, seq, **details))

    def _live_client(self, client_id: str) -> None:
        """Fail-closed: client must not be withdrawn."""
        if client_id in self._withdrawn:
            raise WithdrawnError(
                f"client withdrawn, id never recycled: {client_id!r}")

    def _known_client(self, client_id: str) -> None:
        self._live_client(client_id)
        if not any(key[0] == client_id for key in self._assessments):
            raise UnknownClientError(f"unknown client: {client_id!r}")

    # -- assess ---------------------------------------------------------------

    def assess(
        self,
        body_id: str,
        client_id: str,
        assessment_id: str,
        module: str,
        seq: int,
        outcome: str = "pass",
        scope_digest: str = "",
        assessor_digest: str = "",
    ) -> AssessmentRecord:
        """Declare one conformity assessment run by a notified body.

        The declared ``outcome`` is booked as data (GIGO), never proof of
        real conformity. Scope and assessor identities travel as
        ``sha256:`` digest pins only.
        """
        with self._lock:
            try:
                self._claim(seq)
            except NotifiedBodyError:
                raise
            try:
                _require_id(body_id, "body_id", BadBodyError)
                _require_id(client_id, "client_id", BadClientError)
                _require_id(assessment_id, "assessment_id", BadIdError)
                self._live_client(client_id)
                if module not in MODULES:
                    raise BadModuleError(f"module must be one of {MODULES}")
                if outcome not in ASSESSMENT_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {ASSESSMENT_OUTCOMES}")
                scope_digest = _pin_or_default(scope_digest, "scope_digest")
                assessor_digest = _pin_or_default(
                    assessor_digest, "assessor_digest")
                if (client_id, assessment_id) in self._assessments:
                    raise DuplicateAssessmentError(
                        f"assessment already booked: {assessment_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "body_id": body_id,
                        "client_id": client_id,
                        "assessment_id": assessment_id,
                        "module": module,
                        "outcome": outcome,
                        "scope_digest": scope_digest,
                        "assessor_digest": assessor_digest,
                    }
                )
                record = AssessmentRecord(
                    body_id=body_id, client_id=client_id,
                    assessment_id=assessment_id, module=module,
                    outcome=outcome, scope_digest=scope_digest,
                    assessor_digest=assessor_digest, digest=digest,
                )
                self._assessments[(client_id, assessment_id)] = record
                self._emit(
                    "assessed", seq, assessment_id=assessment_id,
                    module=module, outcome=outcome,
                )
                return record
            except NotifiedBodyError:
                self._burn(seq, "assess")
                raise

    # -- certify ----------------------------------------------------------------

    def certify(
        self,
        client_id: str,
        seq: int,
        validity_years: int = 5,
        assessor_digest: str = "",
    ) -> CertificationRecord:
        """Declare a certificate granted by the notified body.

        Fail-closed: requires a booked assessment with outcome ``pass``
        for the same client; refuses if already certified or withdrawn.
        Certificate ids are minted ``cert-N``.
        """
        with self._lock:
            try:
                self._claim(seq)
            except NotifiedBodyError:
                raise
            try:
                _require_id(client_id, "client_id", BadClientError)
                self._known_client(client_id)
                if client_id in self._certs:
                    raise AlreadyCertifiedError(
                        f"client already certified: {client_id!r}")
                if (isinstance(validity_years, bool)
                        or validity_years not in VALIDITY_YEARS):
                    raise BadValidityError(
                        f"validity_years must be one of {VALIDITY_YEARS}")
                assessor_digest = _pin_or_default(
                    assessor_digest, "assessor_digest")
                basis = None
                for (cid, aid), record in self._assessments.items():
                    if cid == client_id and record.outcome == "pass":
                        basis = aid
                        break
                if basis is None:
                    raise NotEligibleError(
                        f"no booked 'pass' assessment for client: {client_id!r}")
                self._cert_counter += 1
                certificate_id = f"cert-{self._cert_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "client_id": client_id,
                        "certificate_id": certificate_id,
                        "basis_assessment_id": basis,
                        "validity_years": validity_years,
                        "assessor_digest": assessor_digest,
                    }
                )
                record = CertificationRecord(
                    client_id=client_id, certificate_id=certificate_id,
                    basis_assessment_id=basis,
                    validity_years=validity_years,
                    assessor_digest=assessor_digest, digest=digest,
                )
                self._certs[client_id] = record
                self._emit(
                    "certified", seq, certificate_id=certificate_id,
                    basis_assessment_id=basis,
                )
                return record
            except NotifiedBodyError:
                self._burn(seq, "certify")
                raise

    # -- surveil ------------------------------------------------------------------

    def surveil(
        self,
        client_id: str,
        year: int,
        seq: int,
        outcome: str = "maintain",
        assessor_digest: str = "",
    ) -> SurveillanceRecord:
        """Book one declared surveillance audit (years 1..4).

        Requires a live certificate. Declared ``outcome`` is booked as
        data, never proof of a real audit visit.
        """
        with self._lock:
            try:
                self._claim(seq)
            except NotifiedBodyError:
                raise
            try:
                _require_id(client_id, "client_id", BadClientError)
                self._live_client(client_id)
                if client_id not in self._certs:
                    raise NotCertifiedError(
                        f"no live certificate for client: {client_id!r}")
                if isinstance(year, bool) or year not in SURVEILLANCE_YEARS:
                    raise BadYearError(
                        f"year must be one of {SURVEILLANCE_YEARS}")
                if outcome not in SURVEILLANCE_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {SURVEILLANCE_OUTCOMES}")
                assessor_digest = _pin_or_default(
                    assessor_digest, "assessor_digest")
                if (client_id, year) in self._surv:
                    raise DuplicateSurveillanceError(
                        f"surveillance already booked: {client_id!r} year {year}")
                self._svl_counter += 1
                surveillance_id = f"svl-{self._svl_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "surveillance_id": surveillance_id,
                        "client_id": client_id,
                        "year": year,
                        "outcome": outcome,
                        "assessor_digest": assessor_digest,
                    }
                )
                record = SurveillanceRecord(
                    surveillance_id=surveillance_id, client_id=client_id,
                    year=year, outcome=outcome,
                    assessor_digest=assessor_digest, digest=digest,
                )
                self._surv[(client_id, year)] = record
                self._emit(
                    "surveiled", seq, surveillance_id=surveillance_id,
                    year=year, outcome=outcome,
                )
                return record
            except NotifiedBodyError:
                self._burn(seq, "surveil")
                raise

    # -- withdraw -----------------------------------------------------------------

    def withdraw(self, client_id: str, seq: int, reason: str = "manual"
                 ) -> WithdrawalRecord:
        """Withdraw a certificate (terminal; ids never recycled)."""
        with self._lock:
            try:
                self._claim(seq)
            except NotifiedBodyError:
                raise
            try:
                _require_id(client_id, "client_id", BadClientError)
                if reason not in WITHDRAW_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {WITHDRAW_REASONS}")
                self._live_client(client_id)
                if client_id in self._withdrawn:
                    raise WithdrawnError(
                        f"client already withdrawn: {client_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "client_id": client_id,
                        "reason": reason,
                    }
                )
                record = WithdrawalRecord(
                    client_id=client_id, reason=reason, digest=digest)
                self._withdrawn.add(client_id)
                self._withdrawals[client_id] = record
                self._emit("withdrawn", seq, reason=reason)
                return record
            except NotifiedBodyError:
                self._burn(seq, "withdraw")
                raise

    # -- views --------------------------------------------------------------------

    def status(self, client_id: str, seq: int) -> CertificateStatus:
        """Certification posture for a client (pure read)."""
        with self._lock:
            self._view_seq(seq)
            cid = _require_id(client_id, "client_id", BadClientError)
            relevant = [
                record for (key_cid, _), record in self._assessments.items()
                if key_cid == cid
            ]
            has_passing = any(r.outcome == "pass" for r in relevant)
            n_surv = sum(1 for (svl_cid, _) in self._surv if svl_cid == cid)
            integrity_ok = all(r.verify() for r in relevant)
            integrity_ok = integrity_ok and all(
                r.verify() for (svl_cid, _), r in self._surv.items()
                if svl_cid == cid
            )
            if cid in self._withdrawn:
                posture = "withdrawn"
            elif cid in self._certs:
                posture = "certified"
            elif relevant:
                posture = "not-certified"
            else:
                posture = "unknown"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "client_id": cid,
                    "posture": posture,
                    "n_assessments": len(relevant),
                    "has_passing_assessment": has_passing,
                    "n_surveillance": n_surv,
                    "integrity_ok": integrity_ok,
                }
            )
            return CertificateStatus(
                client_id=cid, posture=posture,
                n_assessments=len(relevant),
                has_passing_assessment=has_passing,
                n_surveillance=n_surv, integrity_ok=integrity_ok,
                digest=digest,
            )

    def assessment_record(
        self, client_id: str, assessment_id: str, seq: int
    ) -> AssessmentRecord:
        """Return one assessment record (pure read)."""
        with self._lock:
            self._view_seq(seq)
            cid = _require_id(client_id, "client_id", BadClientError)
            aid = _require_id(assessment_id, "assessment_id", BadIdError)
            try:
                return self._assessments[(cid, aid)]
            except KeyError:
                raise UnknownAssessmentError(
                    f"unknown assessment: {aid!r}") from None

    def certificate_record(self, client_id: str, seq: int
                           ) -> CertificationRecord:
        """Return one certificate record (pure read)."""
        with self._lock:
            self._view_seq(seq)
            cid = _require_id(client_id, "client_id", BadClientError)
            if cid not in self._certs:
                raise NotCertifiedError(
                    f"no live certificate for client: {cid!r}")
            return self._certs[cid]

    def withdrawal_record(self, client_id: str, seq: int) -> WithdrawalRecord:
        """Return one withdrawal record (pure read)."""
        with self._lock:
            self._view_seq(seq)
            cid = _require_id(client_id, "client_id", BadClientError)
            if cid not in self._withdrawals:
                raise UnknownClientError(f"unknown client: {cid!r}")
            return self._withdrawals[cid]

    def client_ids(self, seq: int) -> Tuple[str, ...]:
        """All client ids seen by the ledger (assessment order)."""
        with self._lock:
            self._view_seq(seq)
            seen: List[str] = []
            for cid, _ in self._assessments:
                if cid not in seen:
                    seen.append(cid)
            return tuple(seen)

    def certified_ids(self, seq: int) -> Tuple[str, ...]:
        """Clients holding a live certificate."""
        with self._lock:
            self._view_seq(seq)
            return tuple(
                cid for cid in self._certs if cid not in self._withdrawn)

    def assessments_for(self, client_id: str, seq: int) -> Tuple[str, ...]:
        """Assessment ids booked for one client."""
        with self._lock:
            self._view_seq(seq)
            cid = _require_id(client_id, "client_id", BadClientError)
            return tuple(
                aid for (key_cid, aid) in self._assessments
                if key_cid == cid)

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._view_seq(seq)
            rejected = sum(
                1 for row in self._audit if row.get("kind") == "rejected")
            return {
                "assessments": len(self._assessments),
                "certificates": len(self._certs),
                "surveillance": len(self._surv),
                "withdrawals": len(self._withdrawals),
                "rejected": rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    nb = NotifiedBody()
    nb.assess("nb-100", "client-1", "a-1", "module-b", 1, outcome="pass")
    cert = nb.certify("client-1", 2, validity_years=5)
    nb.surveil("client-1", 1, 3, outcome="maintain")
    status = nb.status("client-1", 4)
    assert cert.verify()
    assert status.verify()
    assert status.posture == "certified"
    assert status.n_assessments == 1
    assert status.n_surveillance == 1
    assert status.integrity_ok is True
    assert nb.stats(5) == {
        "assessments": 1, "certificates": 1, "surveillance": 1,
        "withdrawals": 0, "rejected": 0,
    }
    print("notified-body OK: assess, certify, surveil, status, pins, audit")


if __name__ == "__main__":
    main()
