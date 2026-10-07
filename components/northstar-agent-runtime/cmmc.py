"""CMMC certification decision ledger: systems, practice assessments, POA&M, certification.

A ``CMMC`` books a declared Cybersecurity Maturity Model Certification
workflow -- system registration under a pinned CMMC level, host-declared
practice assessments, declared remediations (POA&M -- plan of action and
milestones) against ``not-met`` practices, and derived certification
postures -- as a deterministic single-host state machine. This module
owns the *certification decision ledger* layer, deliberately distinct
from siblings:

* ``compliance.py`` -- generic compliance framework governance ledger.
* ``grc.py`` -- GRC governance workflow ledger.
* ``audit_management.py`` -- audit engagement management.
* This module -- which system targeted which CMMC level, what each
  booked practice assessment declared, which ``not-met`` findings have
  a booked remediation, and what the derived certification posture is.

Workflow:

1. ``register_system(system_id, level, seq, ...)`` declares one system
   under a pinned CMMC level (``level-1`` / ``level-2`` / ``level-3``);
   raw scope descriptions never enter the ledger -- digest pins only.
2. ``assess(system_id, practice_id, result, seq, ...)`` books one
   host-declared practice assessment (minted ``asm-N``); results are
   *data* (``met`` / ``not-met`` / ``not-applicable``), never proof of
   an actual assessment outcome.
3. ``remediate(assessment_id, action, seq, ...)`` books one declared
   POA&M remediation against a ``not-met`` assessment (minted
   ``rmd-N``); one remediation per assessment; books the *declaration*,
   never the actual fix.
4. ``certify(system_id, seq)`` is a pure read deriving the
   certification posture as data (``certified`` / ``not-certified`` /
   ``not-assessed``) from the booked assessments and remediations.

House style: frozen dataclasses, caller-supplied int seqs strictly
increasing (claim-then-burn: failed mutations consume their seq and
book ``cmmc.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only (plus the
sanctioned ``canonical_json`` try/except fallback), ``sha256:`` digest
pins with ``verify()``, ``audit.ndjson/1`` events with raw practice and
scope content banned from the audit boundary, version/schema pins,
``main()`` self-check.

Honest scope: assessments are host-declared GIGO -- a booked ``met``
means the host declared this outcome, never that a practice is actually
satisfied. Certification books a declared posture derived from ledger
truth, never proof of certification standing. This module runs no
assessor, contacts no C3PAO, and proves nothing about regulatory
standing. Practice counts per level (L1: 17, L2: 110, L3: 134) are
booked as documentary metadata, never as an enforced checklist.

Version pin: cmmc.v1
Schema pin: northstar.cmmc.v1
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
CMMC_VERSION = "cmmc.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.cmmc.v1"

#: Schema pin for audit rows.
AUDIT_SCHEMA = "audit.ndjson/1"

#: CMMC level vocabulary (documentary practice counts per level).
LEVEL_1 = "level-1"
LEVEL_2 = "level-2"
LEVEL_3 = "level-3"
_LEVELS = frozenset({LEVEL_1, LEVEL_2, LEVEL_3})
_LEVEL_PRACTICE_COUNTS = {
    LEVEL_1: 17,
    LEVEL_2: 110,
    LEVEL_3: 134,
}

#: Practice-assessment result vocabulary (booked as data, never proof).
RESULT_MET = "met"
RESULT_NOT_MET = "not-met"
RESULT_NA = "not-applicable"
_RESULTS = frozenset({RESULT_MET, RESULT_NOT_MET, RESULT_NA})

#: POA&M remediation-action vocabulary.
ACTION_FIX_CONTROL = "fix-control"
ACTION_DOCUMENT = "document"
ACTION_ACCEPT_RISK = "accept-risk"
ACTION_ESCALATE = "escalate"
ACTION_REASSESS = "reassess"
ACTION_POLICY_UPDATE = "policy-update"
_ACTIONS = frozenset(
    {
        ACTION_FIX_CONTROL,
        ACTION_DOCUMENT,
        ACTION_ACCEPT_RISK,
        ACTION_ESCALATE,
        ACTION_REASSESS,
        ACTION_POLICY_UPDATE,
    }
)

#: Audit event kinds.
KIND_REGISTERED = "cmmc.registered"
KIND_ASSESSED = "cmmc.assessed"
KIND_REMEDIATED = "cmmc.remediated"
KIND_REJECTED = "cmmc.rejected"

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
        "description",
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
        "finding",
        "details",
        "plan",
    }
)


class CMMCError(Exception):
    """Base fail-closed error for the CMMC ledger."""


class BadIdError(CMMCError):
    """Malformed system, practice, or record id."""


class DuplicateSystemError(CMMCError):
    """System id already registered in this ledger."""


class UnknownSystemError(CMMCError):
    """System id not known to this ledger."""


class BadLevelError(CMMCError):
    """CMMC level outside the pinned vocabulary."""


class BadDigestError(CMMCError):
    """Digest is not a sha256 pin."""


class BadResultError(CMMCError):
    """Assessment result outside the pinned vocabulary."""


class BadActionError(CMMCError):
    """Remediation action outside the pinned vocabulary."""


class UnknownAssessmentError(CMMCError):
    """Assessment id not known to this ledger."""


class RemediationNotNeededError(CMMCError):
    """Remediation booked against a non-failing assessment."""


class AlreadyRemediatedError(CMMCError):
    """Assessment already has a booked remediation."""


class SeqOrderError(CMMCError):
    """Caller seq did not strictly increase."""


class AuditKindError(CMMCError):
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


def cmmc_audit_event(audit_kind: str, detail: Dict[str, object],
                     seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the CMMC ledger."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": CMMC_VERSION,
        "kind": audit_kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class SystemRecord:
    """Frozen record of one registered system under a CMMC level."""

    system_id: str
    level: str
    scope_digest: str
    seq: int
    digest: str

    def verify(self, system_id: str, level: str,
               scope_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("system", system_id, level, scope_digest)
        return self.digest == expect


@dataclass(frozen=True)
class AssessmentRecord:
    """Frozen record of one declared practice assessment (minted asm-N)."""

    assessment_id: str
    system_id: str
    practice_id: str
    result: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self, system_id: str, practice_id: str, result: str,
               evidence_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("assessment", system_id, practice_id, result,
                      evidence_digest)
        return self.digest == expect


@dataclass(frozen=True)
class RemediationRecord:
    """Frozen record of one declared POA&M remediation (minted rmd-N)."""

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
class CertificationReport:
    """Frozen derived certification posture for one system.

    ``posture`` is data: ``certified`` (at least one assessed practice
    and no unremediated ``not-met`` findings), ``not-certified`` (at
    least one unremediated ``not-met`` finding), or ``not-assessed`` (no
    booked assessments).
    """

    system_id: str
    level: str
    posture: str
    n_assessments: int
    n_met: int
    n_not_met: int
    n_remediated: int
    seq: int
    digest: str

    def verify(self, system_id: str, level: str, posture: str,
               n_assessments: int, n_met: int, n_not_met: int,
               n_remediated: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("certification", system_id, level, posture,
                      n_assessments, n_met, n_not_met, n_remediated)
        return self.digest == expect


class CMMC:
    """CMMC certification decision ledger: register, assess, remediate, certify.

    Deterministic single-host state machine. Caller-supplied seqs must
    strictly increase; failed mutations consume their seq and book a
    ``cmmc.rejected`` audit row; rewinds raise bare. Pure-read views
    validate seq shape, never consume, and write no audit rows.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._systems: Dict[str, SystemRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._remediations: Dict[str, RemediationRecord] = {}
        self._assessments_by_system: Dict[str, List[str]] = {}
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
        self._audit.append(cmmc_audit_event(audit_kind, detail, seq))

    def _reject(self, seq: int, reason: str) -> None:
        """Book a rejected-mutation row (claim-then-burn)."""
        self._emit(KIND_REJECTED, {"reason": reason}, seq)

    # -- mutations ---------------------------------------------------

    def register_system(self, system_id: str, level: str, seq: object,
                        scope_digest: str = "") -> SystemRecord:
        """Declare one system under a CMMC level; raw scope stays out."""
        with self._lock:
            seq = self._claim(seq)
            try:
                system_id = _check_id("system_id", system_id)
                if level not in _LEVELS:
                    raise BadLevelError(
                        f"level {level!r} outside pinned vocabulary")
                scope_digest = _check_optional_digest("scope_digest",
                                                      scope_digest)
                if system_id in self._systems:
                    raise DuplicateSystemError(
                        f"system already registered: {system_id!r}")
                rec = SystemRecord(
                    system_id=system_id,
                    level=level,
                    scope_digest=scope_digest,
                    seq=seq,
                    digest=_pin("system", system_id, level, scope_digest),
                )
            except CMMCError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            self._systems[system_id] = rec
            self._assessments_by_system[system_id] = []
            self._emit(KIND_REGISTERED,
                       {"system_id": system_id, "level": level},
                       seq)
            return rec

    def assess(self, system_id: str, practice_id: str, result: str,
               seq: object, evidence_digest: str = "") -> AssessmentRecord:
        """Book one declared practice assessment (minted asm-N id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                system_id = _check_id("system_id", system_id)
                practice_id = _check_id("practice_id", practice_id)
                if system_id not in self._systems:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                if result not in _RESULTS:
                    raise BadResultError(
                        f"result {result!r} outside pinned vocabulary")
                evidence_digest = _check_optional_digest("evidence_digest",
                                                          evidence_digest)
                assessment_id = f"asm-{self._next_assessment}"
                self._next_assessment += 1
                rec = AssessmentRecord(
                    assessment_id=assessment_id,
                    system_id=system_id,
                    practice_id=practice_id,
                    result=result,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_pin("assessment", system_id, practice_id,
                                result, evidence_digest),
                )
            except CMMCError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            self._assessments[assessment_id] = rec
            self._assessments_by_system[system_id].append(assessment_id)
            self._emit(KIND_ASSESSED,
                       {"assessment_id": assessment_id,
                        "system_id": system_id,
                        "practice_id": practice_id, "result": result},
                       seq)
            return rec

    def remediate(self, assessment_id: str, action: str, seq: object,
                  detail_digest: str = "") -> RemediationRecord:
        """Book one declared POA&M remediation against a not-met assessment."""
        with self._lock:
            seq = self._claim(seq)
            try:
                assessment_id = _check_id("assessment_id", assessment_id)
                if assessment_id not in self._assessments:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}")
                asm = self._assessments[assessment_id]
                if asm.result != RESULT_NOT_MET:
                    raise RemediationNotNeededError(
                        f"assessment {assessment_id!r} result "
                        f"{asm.result!r} is not failing")
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
            except CMMCError as exc:
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

    def certify(self, system_id: str, seq: object) -> CertificationReport:
        """Derive the certification posture for one system (pure read)."""
        with self._lock:
            _check_id("system_id", system_id)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            _check_seq(seq)  # shape validated, never consumed
            level = self._systems[system_id].level
            ids = self._assessments_by_system.get(system_id, [])
            n_assessments = len(ids)
            n_met = 0
            n_not_met = 0
            n_remediated = 0
            for aid in ids:
                asm = self._assessments[aid]
                if asm.result == RESULT_MET:
                    n_met += 1
                elif asm.result == RESULT_NOT_MET:
                    n_not_met += 1
                    if aid in self._remediation_by_assessment:
                        n_remediated += 1
            unremediated = n_not_met - n_remediated
            if n_assessments == 0:
                posture = "not-assessed"
            elif unremediated > 0:
                posture = "not-certified"
            else:
                posture = "certified"
            return CertificationReport(
                system_id=system_id,
                level=level,
                posture=posture,
                n_assessments=n_assessments,
                n_met=n_met,
                n_not_met=n_not_met,
                n_remediated=n_remediated,
                seq=seq,
                digest=_pin("certification", system_id, level, posture,
                            n_assessments, n_met, n_not_met, n_remediated),
            )

    def system_record(self, system_id: str, seq: object) -> SystemRecord:
        """Pure read: one system record."""
        with self._lock:
            _check_seq(seq)
            _check_id("system_id", system_id)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._systems[system_id]

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

    def system_ids(self, seq: object) -> Tuple[str, ...]:
        """Pure read: registered system ids, sorted."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._systems))

    def assessments_for(self, system_id: str,
                        seq: object) -> Tuple[str, ...]:
        """Pure read: assessment ids for one system, insertion order."""
        with self._lock:
            _check_seq(seq)
            _check_id("system_id", system_id)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return tuple(self._assessments_by_system[system_id])

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
                "systems": len(self._systems),
                "assessments": len(self._assessments),
                "remediations": len(self._remediations),
                "rejected": sum(1 for row in self._audit
                                if row["kind"] == KIND_REJECTED),
            }

    def level_practice_count(self, level: str, seq: object) -> int:
        """Pure read: documentary practice count for one CMMC level."""
        with self._lock:
            _check_seq(seq)
            if level not in _LEVELS:
                raise BadLevelError(
                    f"level {level!r} outside pinned vocabulary")
            return _LEVEL_PRACTICE_COUNTS[level]


def main() -> None:
    """Self-check smoke run."""
    c = CMMC()
    c.register_system("sys-1", LEVEL_2, 1)
    c.assess("sys-1", "AC.L2-3.1.1", RESULT_MET, 2)
    c.assess("sys-1", "AC.L2-3.1.2", RESULT_NOT_MET, 3)
    c.remediate("asm-2", ACTION_FIX_CONTROL, 4)
    rep = c.certify("sys-1", 5)
    assert rep.posture == "certified", rep.posture
    assert rep.verify("sys-1", LEVEL_2, "certified", 2, 1, 1, 1)
    print("cmmc OK: register, assess, remediate, certify, pins, audit")


if __name__ == "__main__":
    main()
