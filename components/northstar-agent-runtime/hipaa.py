"""HIPAA Security Rule safeguard ledger: entities, assessments, remediation, attestation.

A ``HIPAA`` books a declared HIPAA compliance workflow -- entity
registration, safeguard assessments across the Security Rule's three
categories (administrative / physical / technical), declared remediation
of unsatisfied safeguards, and derived compliance attestations -- as a
deterministic single-host state machine. This module owns the *HIPAA
safeguard decision ledger* layer, deliberately distinct from siblings:

* ``compliance.py`` -- generic framework/check/remediate ledger.
* ``compliance_checker.py`` -- control-assessment mechanics.
* ``audit_management.py`` -- audit-engagement management.
* This module -- which entity registered, which safeguards were
  assessed under which category, what each assessment declared, which
  unsatisfied safeguards were remediated, and what the derived HIPAA
  posture is.

Workflow:

1. ``register_entity(entity_id, seq, entity_kind, ...)`` declares one
   covered entity / business associate; raw PHI and profile text never
   enter the ledger -- digest pins only.
2. ``assess(entity_id, safeguard_id, category, seq, finding, ...)``
   books one host-declared safeguard assessment (minted ``asm-N``);
   findings are *data* (``satisfied`` / ``not-satisfied`` /
   ``partially-satisfied`` / ``not-applicable``), never proof of real
   compliance.
3. ``remediate(assessment_id, action, seq, ...)`` books one declared
   remediation against an unsatisfied assessment (minted ``rmd-N``);
   one remediation per assessment; books the *declaration*, never the
   actual fix.
4. ``attest(entity_id, seq)`` is a pure read deriving the HIPAA posture
   as data (``compliant`` / ``non-compliant`` / ``not-assessed``) from
   the booked assessments and remediations.

House style: frozen dataclasses, caller-supplied int seqs strictly
increasing (claim-then-burn: failed mutations consume their seq and
book ``hipaa.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only (plus the
sanctioned ``canonical_json`` try/except fallback), ``sha256:`` digest
pins with ``verify()``, ``audit.ndjson/1`` events with raw PHI and
profile content banned from the audit boundary, version/schema pins,
``main()`` self-check.

Honest scope: assessments are host-declared GIGO -- a booked
``satisfied`` means the host declared this outcome, never that a
safeguard is actually implemented. Attestation books a declared posture
derived from ledger truth, never proof of OCR audit readiness. This
module runs no scanner, sees no PHI, contacts no regulator, and proves
nothing about regulatory standing.

Version pin: hipaa.v1
Schema pin: northstar.hipaa.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Dict, List, Tuple

try:  # pragma: no cover - repo may ship canonical_json as a module
    from canonical_json import jcs_dumps as _jcs_dumps
except Exception:  # pragma: no cover - stdlib fallback
    import json as _json

    def _jcs_dumps(obj) -> str:
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True)

#: Module version pin.
HIPAA_VERSION = "hipaa.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.hipaa.v1"

#: Schema pin for audit rows.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Entity-kind vocabulary.
ENTITY_COVERED = "covered-entity"
ENTITY_ASSOCIATE = "business-associate"
ENTITY_SUBCONTRACTOR = "subcontractor"
_ENTITY_KINDS = frozenset(
    {
        ENTITY_COVERED,
        ENTITY_ASSOCIATE,
        ENTITY_SUBCONTRACTOR,
    }
)

#: Security Rule safeguard-category vocabulary.
CAT_ADMINISTRATIVE = "administrative"
CAT_PHYSICAL = "physical"
CAT_TECHNICAL = "technical"
_CATEGORIES = frozenset(
    {
        CAT_ADMINISTRATIVE,
        CAT_PHYSICAL,
        CAT_TECHNICAL,
    }
)

#: Assessment-finding vocabulary (booked as data, never proof).
FINDING_SATISFIED = "satisfied"
FINDING_NOT_SATISFIED = "not-satisfied"
FINDING_PARTIAL = "partially-satisfied"
FINDING_NA = "not-applicable"
_FINDINGS = frozenset(
    {
        FINDING_SATISFIED,
        FINDING_NOT_SATISFIED,
        FINDING_PARTIAL,
        FINDING_NA,
    }
)

#: Findings that count as unsatisfied for remediation/posture purposes.
_UNSATISFIED = frozenset({FINDING_NOT_SATISFIED, FINDING_PARTIAL})

#: Remediation-action vocabulary.
ACTION_PATCH = "patch"
ACTION_RECONFIGURE = "reconfigure"
ACTION_TRAINING = "training"
ACTION_POLICY_UPDATE = "policy-update"
ACTION_DOCUMENT = "document"
ACTION_MITIGATE = "mitigate"
ACTION_ESCALATE = "escalate"
_ACTIONS = frozenset(
    {
        ACTION_PATCH,
        ACTION_RECONFIGURE,
        ACTION_TRAINING,
        ACTION_POLICY_UPDATE,
        ACTION_DOCUMENT,
        ACTION_MITIGATE,
        ACTION_ESCALATE,
    }
)

#: Audit event kinds.
KIND_REGISTERED = "hipaa.registered"
KIND_ASSESSED = "hipaa.assessed"
KIND_REMEDIATED = "hipaa.remediated"
KIND_REJECTED = "hipaa.rejected"

_KINDS = frozenset(
    {
        KIND_REGISTERED,
        KIND_ASSESSED,
        KIND_REMEDIATED,
        KIND_REJECTED,
    }
)

#: Detail keys that must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset(
    {
        "phi",
        "profile",
        "raw",
        "content",
        "payload",
        "evidence",
        "notes",
        "note",
        "transcript",
        "data",
        "value",
        "values",
        "text",
        "description",
        "remediation",
        "details",
        "patient",
        "record",
        "health",
        "ephi",
    }
)


class HIPAAError(Exception):
    """Base fail-closed error for the HIPAA safeguard ledger."""


class BadIdError(HIPAAError):
    """Malformed entity, safeguard, or record id."""


class DuplicateEntityError(HIPAAError):
    """Entity id already registered in this ledger."""


class UnknownEntityError(HIPAAError):
    """Entity id not known to this ledger."""


class BadEntityKindError(HIPAAError):
    """Entity kind outside the pinned vocabulary."""


class BadCategoryError(HIPAAError):
    """Safeguard category outside the pinned vocabulary."""


class BadDigestError(HIPAAError):
    """Digest is not a sha256 pin."""


class BadFindingError(HIPAAError):
    """Assessment finding outside the pinned vocabulary."""


class BadActionError(HIPAAError):
    """Remediation action outside the pinned vocabulary."""


class UnknownAssessmentError(HIPAAError):
    """Assessment id not known to this ledger."""


class AssessmentNotUnsatisfiedError(HIPAAError):
    """Remediation booked against a satisfied / not-applicable assessment."""


class AlreadyRemediatedError(HIPAAError):
    """Assessment already has a booked remediation."""


class SeqOrderError(HIPAAError):
    """Caller seq did not strictly increase."""


class AuditKindError(HIPAAError):
    """Unknown audit kind or banned detail key."""


def _check_seq(seq: object) -> int:
    """Validate a caller-supplied seq (int, non-bool, non-negative)."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_id(name: str, value: object) -> str:
    """Validate a non-empty string identifier."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{name} must be a str, got {type(value).__name__}")
    if not value or len(value) > 256:
        raise BadIdError(f"{name} must be 1..256 chars")
    if value != value.strip():
        raise BadIdError(f"{name} must not have surrounding whitespace")
    return value


def _check_digest(name: str, value: object) -> str:
    """Validate a sha256 digest pin (sha256:<64hex>)."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{name} must be a str, got {type(value).__name__}")
    if not value.startswith("sha256:") or len(value) != 71:
        raise BadDigestError(f"{name} must be 'sha256:' + 64 hex chars")
    try:
        int(value[7:], 16)
    except ValueError:
        raise BadDigestError(f"{name} hex part is not hex") from None
    return value


def _check_optional_digest(name: str, value: object) -> str:
    """Validate an empty string or a sha256 digest pin."""
    if value == "":
        return ""
    return _check_digest(name, value)


def _pin(*parts: object) -> str:
    """Deterministic sha256 pin over canonical JSON of parts."""
    canonical = _jcs_dumps([str(p) for p in parts])
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hipaa_audit_event(audit_kind: str, detail: Dict[str, object],
                      seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the HIPAA ledger."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": HIPAA_VERSION,
        "kind": audit_kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class EntityRecord:
    """Frozen record of one registered entity."""

    entity_id: str
    entity_kind: str
    profile_digest: str
    seq: int
    digest: str

    def verify(self, entity_id: str, entity_kind: str,
               profile_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("entity", entity_id, entity_kind, profile_digest)
        return self.digest == expect


@dataclass(frozen=True)
class AssessmentRecord:
    """Frozen record of one declared safeguard assessment (minted asm-N)."""

    assessment_id: str
    entity_id: str
    safeguard_id: str
    category: str
    finding: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self, entity_id: str, safeguard_id: str, category: str,
               finding: str, evidence_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("assessment", entity_id, safeguard_id, category,
                      finding, evidence_digest)
        return self.digest == expect


@dataclass(frozen=True)
class RemediationRecord:
    """Frozen record of one declared remediation (minted rmd-N)."""

    remediation_id: str
    assessment_id: str
    action: str
    detail_digest: str
    seq: int
    digest: str

    def verify(self, assessment_id: str, action: str,
               detail_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("remediation", assessment_id, action, detail_digest)
        return self.digest == expect


@dataclass(frozen=True)
class AttestationReport:
    """Frozen derived HIPAA posture for one entity.

    ``posture`` is data: ``compliant`` (at least one assessment and no
    unremediated unsatisfied safeguards), ``non-compliant`` (at least
    one unremediated unsatisfied safeguard), or ``not-assessed`` (no
    assessments booked).
    """

    entity_id: str
    posture: str
    n_assessments: int
    n_satisfied: int
    n_unsatisfied: int
    n_remediated: int
    seq: int
    digest: str

    def verify(self, entity_id: str, posture: str, n_assessments: int,
               n_satisfied: int, n_unsatisfied: int,
               n_remediated: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("attestation", entity_id, posture, n_assessments,
                      n_satisfied, n_unsatisfied, n_remediated)
        return self.digest == expect


class HIPAA:
    """HIPAA safeguard decision ledger: register, assess, remediate, attest.

    Deterministic single-host state machine. Caller-supplied seqs must
    strictly increase; failed mutations consume their seq and book a
    ``hipaa.rejected`` audit row; rewinds raise bare. Pure-read views
    validate seq shape, never consume, and write no audit rows.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._entities: Dict[str, EntityRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._remediations: Dict[str, RemediationRecord] = {}
        self._assessments_by_entity: Dict[str, List[str]] = {}
        self._remediation_by_assessment: Dict[str, str] = {}
        self._audit: List[Dict[str, object]] = []
        self._next_assessment = 1
        self._next_remediation = 1

    # -- internal ----------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Shape-validate seq and advance the clock (fail-closed)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} does not strictly increase after "
                f"{self._last_seq}")
        self._last_seq = seq
        return seq

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit row (raw-content keys banned by the builder)."""
        self._audit.append(hipaa_audit_event(audit_kind, detail, seq))

    def _reject(self, seq: int, reason: str) -> None:
        """Book a rejected-mutation row (claim-then-burn)."""
        self._emit(KIND_REJECTED, {"reason": reason}, seq)

    # -- mutations ---------------------------------------------------

    def register_entity(self, entity_id: str, seq: object,
                        entity_kind: str = ENTITY_COVERED,
                        profile_digest: str = "") -> EntityRecord:
        """Declare one covered entity / business associate.

        Raw PHI and profile text never enter the ledger -- digest pins
        only.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                entity_id = _check_id("entity_id", entity_id)
                if entity_kind not in _ENTITY_KINDS:
                    raise BadEntityKindError(
                        f"entity_kind {entity_kind!r} outside pinned "
                        "vocabulary")
                profile_digest = _check_optional_digest("profile_digest",
                                                        profile_digest)
                if entity_id in self._entities:
                    raise DuplicateEntityError(
                        f"entity already registered: {entity_id!r}")
                rec = EntityRecord(
                    entity_id=entity_id,
                    entity_kind=entity_kind,
                    profile_digest=profile_digest,
                    seq=seq,
                    digest=_pin("entity", entity_id, entity_kind,
                                profile_digest),
                )
            except HIPAAError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            self._entities[entity_id] = rec
            self._assessments_by_entity[entity_id] = []
            self._emit(KIND_REGISTERED,
                       {"entity_id": entity_id, "entity_kind": entity_kind},
                       seq)
            return rec

    def assess(self, entity_id: str, safeguard_id: str, category: str,
               seq: object, finding: str = FINDING_SATISFIED,
               evidence_digest: str = "") -> AssessmentRecord:
        """Book one declared safeguard assessment (minted asm-N id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                entity_id = _check_id("entity_id", entity_id)
                safeguard_id = _check_id("safeguard_id", safeguard_id)
                if entity_id not in self._entities:
                    raise UnknownEntityError(
                        f"unknown entity: {entity_id!r}")
                if category not in _CATEGORIES:
                    raise BadCategoryError(
                        f"category {category!r} outside pinned vocabulary")
                if finding not in _FINDINGS:
                    raise BadFindingError(
                        f"finding {finding!r} outside pinned vocabulary")
                evidence_digest = _check_optional_digest("evidence_digest",
                                                         evidence_digest)
                assessment_id = f"asm-{self._next_assessment}"
                self._next_assessment += 1
                rec = AssessmentRecord(
                    assessment_id=assessment_id,
                    entity_id=entity_id,
                    safeguard_id=safeguard_id,
                    category=category,
                    finding=finding,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_pin("assessment", entity_id, safeguard_id,
                                category, finding, evidence_digest),
                )
            except HIPAAError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            self._assessments[assessment_id] = rec
            self._assessments_by_entity[entity_id].append(assessment_id)
            self._emit(KIND_ASSESSED,
                       {"assessment_id": assessment_id,
                        "entity_id": entity_id,
                        "safeguard_id": safeguard_id,
                        "category": category, "finding": finding},
                       seq)
            return rec

    def remediate(self, assessment_id: str, action: str, seq: object,
                  detail_digest: str = "") -> RemediationRecord:
        """Book one declared remediation against an unsatisfied assessment."""
        with self._lock:
            seq = self._claim(seq)
            try:
                assessment_id = _check_id("assessment_id", assessment_id)
                if assessment_id not in self._assessments:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}")
                asm = self._assessments[assessment_id]
                if asm.finding not in _UNSATISFIED:
                    raise AssessmentNotUnsatisfiedError(
                        f"assessment {assessment_id!r} finding "
                        f"{asm.finding!r} is not unsatisfied")
                if assessment_id in self._remediation_by_assessment:
                    raise AlreadyRemediatedError(
                        f"assessment already remediated: {assessment_id!r}")
                if action not in _ACTIONS:
                    raise BadActionError(
                        f"action {action!r} outside pinned vocabulary")
                detail_digest = _check_optional_digest("detail_digest",
                                                       detail_digest)
                remediation_id = f"rmd-{self._next_remediation}"
                self._next_remediation += 1
                rec = RemediationRecord(
                    remediation_id=remediation_id,
                    assessment_id=assessment_id,
                    action=action,
                    detail_digest=detail_digest,
                    seq=seq,
                    digest=_pin("remediation", assessment_id, action,
                                detail_digest),
                )
            except HIPAAError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            self._remediations[remediation_id] = rec
            self._remediation_by_assessment[assessment_id] = remediation_id
            self._emit(KIND_REMEDIATED,
                       {"remediation_id": remediation_id,
                        "assessment_id": assessment_id, "action": action},
                       seq)
            return rec

    # -- pure reads --------------------------------------------------

    def attest(self, entity_id: str, seq: object) -> AttestationReport:
        """Derive the HIPAA posture for one entity (pure read)."""
        with self._lock:
            _check_id("entity_id", entity_id)
            if entity_id not in self._entities:
                raise UnknownEntityError(
                    f"unknown entity: {entity_id!r}")
            _check_seq(seq)  # shape validated, never consumed
            ids = self._assessments_by_entity.get(entity_id, [])
            n_assessments = len(ids)
            n_satisfied = 0
            n_unsatisfied = 0
            n_remediated = 0
            for aid in ids:
                asm = self._assessments[aid]
                if asm.finding in _UNSATISFIED:
                    n_unsatisfied += 1
                    if aid in self._remediation_by_assessment:
                        n_remediated += 1
                elif asm.finding == FINDING_SATISFIED:
                    n_satisfied += 1
            unremediated = n_unsatisfied - n_remediated
            if n_assessments == 0:
                posture = "not-assessed"
            elif unremediated > 0:
                posture = "non-compliant"
            else:
                posture = "compliant"
            return AttestationReport(
                entity_id=entity_id,
                posture=posture,
                n_assessments=n_assessments,
                n_satisfied=n_satisfied,
                n_unsatisfied=n_unsatisfied,
                n_remediated=n_remediated,
                seq=seq,
                digest=_pin("attestation", entity_id, posture, n_assessments,
                            n_satisfied, n_unsatisfied, n_remediated),
            )

    def entity_record(self, entity_id: str, seq: object) -> EntityRecord:
        """Pure read: one entity record."""
        with self._lock:
            _check_seq(seq)
            _check_id("entity_id", entity_id)
            if entity_id not in self._entities:
                raise UnknownEntityError(
                    f"unknown entity: {entity_id!r}")
            return self._entities[entity_id]

    def assessment_record(self, assessment_id: str,
                          seq: object) -> AssessmentRecord:
        """Pure read: one assessment record."""
        with self._lock:
            _check_seq(seq)
            _check_id("assessment_id", assessment_id)
            if assessment_id not in self._assessments:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}")
            return self._assessments[assessment_id]

    def entity_ids(self, seq: object) -> Tuple[str, ...]:
        """Pure read: registered entity ids, sorted."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._entities))

    def assessments_for(self, entity_id: str,
                        seq: object) -> Tuple[str, ...]:
        """Pure read: assessment ids for one entity, insertion order."""
        with self._lock:
            _check_seq(seq)
            _check_id("entity_id", entity_id)
            if entity_id not in self._entities:
                raise UnknownEntityError(
                    f"unknown entity: {entity_id!r}")
            return tuple(self._assessments_by_entity[entity_id])

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        """Pure read: audit rows (no seq consumption, no new rows)."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: object) -> Dict[str, int]:
        """Pure read: ledger counts."""
        with self._lock:
            _check_seq(seq)
            return {
                "entities": len(self._entities),
                "assessments": len(self._assessments),
                "remediations": len(self._remediations),
                "rejected": sum(1 for row in self._audit
                                if row["kind"] == KIND_REJECTED),
            }


def main() -> None:
    """Self-check smoke run."""
    h = HIPAA()
    h.register_entity("org-1", 1)
    h.assess("org-1", "164.308(a)(1)", CAT_ADMINISTRATIVE, 2)
    h.assess("org-1", "164.312(a)(2)(iv)", CAT_TECHNICAL, 3,
             FINDING_NOT_SATISFIED)
    h.remediate("asm-2", ACTION_PATCH, 4)
    rep = h.attest("org-1", 5)
    assert rep.posture == "compliant", rep.posture
    assert rep.verify("org-1", "compliant", 2, 1, 1, 1)
    print("hipaa OK: register, assess, remediate, attest, pins, audit")


if __name__ == "__main__":
    main()
