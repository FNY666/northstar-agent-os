"""AI liability decision ledger: declare liability assessments, book assignments.

Research motivation: AI liability proposals (product liability for AI
defects, operator liability for deployed systems, strict liability for
high-risk applications, vicarious liability, contractual allocation of
risk) all reduce to one operational bookkeeping shape: a named AI
*system* receives declared *liability assessments* (liability theory,
host-reported finding, host-reported severity), and *liability
assignments* (who bears the liability, on what legal basis). A ledger
derives an assignment posture *as data*. This module books that shape.

This module is the *liability* decision ledger, deliberately distinct
from the sibling layers:

- ``ai_governance.py`` owns governance *controls* and *audit decisions*;
- ``ai_safety.py`` owns the safety assessment->mitigation lifecycle;
- ``ai_regulation.py`` owns regulatory assessments and enforcement
  actions;
- ``ai_ethics.py`` owns per-system ethics assessments;
- ``trustworthy_ai.py`` owns framework assessments (EU HLEG / NIST /
  OECD / ISO);
- ``ai_assurance.py`` owns AI-assurance statements and findings;
- this module owns the AI-*liability* decision ledger: which liability
  assessments were declared over named AI systems, which liability
  assignments were booked (assignee + legal basis), and the derived
  liability posture -- all as data, never legal findings.

Public API:

- ``AILiability.assess(system_id, seq, liability_kind=...,
  finding=..., severity=..., assessment_digest="")`` -- book one
  declared liability assessment over a named AI system (minted
  ``asm-N``). First assess registers the system. Liability kind comes
  from the pinned 8-term vocabulary; finding from the pinned 5-term
  vocabulary; severity is a host-reported int in [0, 100] -- all booked
  *as data*, never a legal finding. Raw assessment material never
  enters records: digest pins only.
- ``AILiability.assign(assessment_id, seq, assignee_kind=...,
  basis=..., assignment_digest="")`` -- book one declared liability
  assignment against a booked assessment (minted ``asg-N``). Assignee
  from the pinned 8-term vocabulary; basis from the pinned 4-term
  vocabulary -- booked *as data*, never a determination of who is
  legally liable. Fail-closed on unknown assessments and retired
  systems.
- ``AILiability.verify(record_id, seq)`` -- pure read: re-derive the
  digest pin of one assessment or assignment record; verdict pinned
  ``verified`` / ``tampered`` as data (tamper reported, never raised).
  Seq shape-validated, never consumed, no audit row.
- ``AILiability.evaluate(system_id, seq)`` -- pure read: re-derive the
  ledger-rule liability posture as data for one named system. Seq
  shape-validated, never consumed, no audit row.
- ``AILiability.retire(system_id, seq, reason="manual")`` -- terminal;
  the system id is retired forever and later assess/assign calls
  refuse; reads still work; ids never recycled.

- ``ai_liability_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``assessed`` / ``assigned`` / ``retired`` / ``rejected``).
  Raw liability material never crosses the audit boundary: ids, pinned
  vocabulary values, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``liability_kind`` must be one of the pinned 8 liability kinds.
- ``finding`` must be one of the pinned 5 findings.
- ``severity`` must be an int in [0, 100] (bool refused).
- ``assignee_kind`` must be one of the pinned 8 assignee kinds.
- ``basis`` must be one of the pinned 4 bases.
- digests must be ``sha256:<64hex>`` when supplied.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* liability assessments and
  *host-reported* findings, severities, and assignments. A booked
  ``liable`` finding means the host declared liability -- the module
  adjudicates nothing, investigates nothing, and proves nothing about
  real-world legal liability.
- Digest pins prove record integrity, never legal correctness.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if liability state must survive a restart.
"""

from __future__ import annotations

import ast
import hashlib
import re
import sys
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AI_LIABILITY_VERSION = "ai-liability.v1"

#: Schema pin carried by records and audit events.
AI_LIABILITY_SCHEMA = "northstar.ai-liability.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ASSESSED = "assessed"
KIND_ASSIGNED = "assigned"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_ASSESSED, KIND_ASSIGNED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw liability material).
_BANNED_DETAIL_KEYS = frozenset(
    {"incident", "injury", "harm", "damages", "claim", "lawsuit",
     "evidence", "transcript", "weights", "testimony", "witness",
     "report_text", "notes", "raw", "payload", "content", "document",
     "attachment", "policy_text", "contract", "insurance", "payout",
     "settlement", "complaint", "verdict_text"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned liability-kind vocabulary. Labels, not legal determinations.
KIND_PRODUCT_LIABILITY = "product-liability"
KIND_OPERATOR_LIABILITY = "operator-liability"
KIND_DEVELOPER_LIABILITY = "developer-liability"
KIND_DEPLOYER_LIABILITY = "deployer-liability"
KIND_STRICT_LIABILITY = "strict-liability"
KIND_VICARIOUS_LIABILITY = "vicarious-liability"
KIND_CONTRACTUAL_LIABILITY = "contractual-liability"
KIND_STATUTORY_LIABILITY = "statutory-liability"
LIABILITY_KINDS = (
    KIND_PRODUCT_LIABILITY,
    KIND_OPERATOR_LIABILITY,
    KIND_DEVELOPER_LIABILITY,
    KIND_DEPLOYER_LIABILITY,
    KIND_STRICT_LIABILITY,
    KIND_VICARIOUS_LIABILITY,
    KIND_CONTRACTUAL_LIABILITY,
    KIND_STATUTORY_LIABILITY,
)

#: Pinned finding vocabulary. Findings are host-reported data, never proof.
FINDING_LIABLE = "liable"
FINDING_NOT_LIABLE = "not-liable"
FINDING_SHARED_LIABILITY = "shared-liability"
FINDING_INCONCLUSIVE = "inconclusive"
FINDING_NOT_ASSESSED = "not-assessed"
FINDINGS = (FINDING_LIABLE, FINDING_NOT_LIABLE, FINDING_SHARED_LIABILITY,
            FINDING_INCONCLUSIVE, FINDING_NOT_ASSESSED)

#: Pinned assignee vocabulary. Assignees are declared, never determined.
ASSIGNEE_DEVELOPER = "developer"
ASSIGNEE_DEPLOYER = "deployer"
ASSIGNEE_OPERATOR = "operator"
ASSIGNEE_USER = "user"
ASSIGNEE_MANUFACTURER = "manufacturer"
ASSIGNEE_PROVIDER = "provider"
ASSIGNEE_DISTRIBUTOR = "distributor"
ASSIGNEE_UNASSIGNED = "unassigned"
ASSIGNEE_KINDS = (
    ASSIGNEE_DEVELOPER,
    ASSIGNEE_DEPLOYER,
    ASSIGNEE_OPERATOR,
    ASSIGNEE_USER,
    ASSIGNEE_MANUFACTURER,
    ASSIGNEE_PROVIDER,
    ASSIGNEE_DISTRIBUTOR,
    ASSIGNEE_UNASSIGNED,
)

#: Pinned legal-basis vocabulary. Labels, not legal determinations.
BASIS_FAULT_BASED = "fault-based"
BASIS_STRICT_LIABILITY = "strict-liability"
BASIS_CONTRACTUAL = "contractual"
BASIS_STATUTORY = "statutory"
BASES = (BASIS_FAULT_BASED, BASIS_STRICT_LIABILITY, BASIS_CONTRACTUAL,
         BASIS_STATUTORY)

#: Pinned derived-posture vocabulary (ledger rule, as data).
POSTURE_UNEVALUATED = "unevaluated"
POSTURE_LIABILITY_OPEN = "liability-open"
POSTURE_CONTESTED = "contested"
POSTURE_UNASSESSED = "unassessed"
POSTURE_CLEARED = "cleared"
POSTURES = (POSTURE_UNEVALUATED, POSTURE_LIABILITY_OPEN,
            POSTURE_CONTESTED, POSTURE_UNASSESSED, POSTURE_CLEARED)

#: Pinned retire-reason vocabulary.
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_DECOMMISSIONED = "decommissioned"
REASON_SETTLED = "settled"
RETIRE_REASONS = (REASON_MANUAL, REASON_SUPERSEDED,
                  REASON_DECOMMISSIONED, REASON_SETTLED)

#: Regex for a well-formed sha256 digest pin.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AILiabilityError(Exception):
    """Base error for the ai-liability module."""


class BadSystemError(AILiabilityError):
    """Malformed system id."""


class UnknownSystemError(AILiabilityError):
    """System id not under liability assessment."""


class RetiredSystemError(AILiabilityError):
    """System id was retired; never recycled."""


class BadLiabilityKindError(AILiabilityError):
    """Liability kind outside the pinned vocabulary."""


class BadFindingError(AILiabilityError):
    """Finding outside the pinned vocabulary."""


class BadSeverityError(AILiabilityError):
    """Severity not a host-reported int in [0, 100]."""


class BadDigestError(AILiabilityError):
    """Malformed sha256 digest pin."""


class BadAssigneeKindError(AILiabilityError):
    """Assignee kind outside the pinned vocabulary."""


class BadBasisError(AILiabilityError):
    """Legal basis outside the pinned vocabulary."""


class BadReasonError(AILiabilityError):
    """Retire reason outside the pinned vocabulary."""


class UnknownAssessmentError(AILiabilityError):
    """Assessment id not booked."""


class UnknownAssignmentError(AILiabilityError):
    """Assignment id not booked."""


class SeqOrderError(AILiabilityError):
    """Seq not a strictly increasing int."""


class AuditKindError(AILiabilityError):
    """Audit kind outside the pinned vocabulary or banned detail key."""


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AssessmentRecord:
    """One declared liability assessment over a named AI system."""
    assessment_id: str
    system_id: str
    liability_kind: str
    finding: str
    severity: int
    assessment_digest: str
    seq: int
    digest: str
    schema: str = AI_LIABILITY_SCHEMA
    version: str = AI_LIABILITY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "system_id": self.system_id,
            "liability_kind": self.liability_kind,
            "finding": self.finding,
            "severity": self.severity,
            "assessment_digest": self.assessment_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        """Recompute the tamper-evident pin."""
        return self.digest == _assessment_digest(
            self.assessment_id, self.system_id, self.liability_kind,
            self.finding, self.severity, self.assessment_digest)


@dataclass(frozen=True)
class AssignmentRecord:
    """One declared liability assignment against a booked assessment."""
    assignment_id: str
    assessment_id: str
    system_id: str
    assignee_kind: str
    basis: str
    assignment_digest: str
    seq: int
    digest: str
    schema: str = AI_LIABILITY_SCHEMA
    version: str = AI_LIABILITY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "assessment_id": self.assessment_id,
            "system_id": self.system_id,
            "assignee_kind": self.assignee_kind,
            "basis": self.basis,
            "assignment_digest": self.assignment_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        """Recompute the tamper-evident pin."""
        return self.digest == _assignment_digest(
            self.assignment_id, self.assessment_id, self.system_id,
            self.assignee_kind, self.basis, self.assignment_digest)


@dataclass(frozen=True)
class VerificationReport:
    """Pure read view of one record's integrity (data, not proof)."""
    record_id: str
    verdict: str  # "verified" | "tampered"
    integrity_ok: bool
    seq: int
    digest: str
    schema: str = AI_LIABILITY_SCHEMA
    version: str = AI_LIABILITY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _verify_digest(self.record_id, self.verdict)


@dataclass(frozen=True)
class EvaluationReport:
    """Pure read view of derived liability posture (data, not findings)."""
    system_id: str
    posture: str  # "unevaluated" | "liability-open" | "contested"
                  # | "unassessed" | "cleared"
    assessment_count: int
    assignment_count: int
    liable_count: int
    not_liable_count: int
    shared_count: int
    inconclusive_count: int
    not_assessed_count: int
    integrity_ok: bool
    assessment_ids: Tuple[str, ...]
    assignment_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = AI_LIABILITY_SCHEMA
    version: str = AI_LIABILITY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "posture": self.posture,
            "assessment_count": self.assessment_count,
            "assignment_count": self.assignment_count,
            "liable_count": self.liable_count,
            "not_liable_count": self.not_liable_count,
            "shared_count": self.shared_count,
            "inconclusive_count": self.inconclusive_count,
            "not_assessed_count": self.not_assessed_count,
            "integrity_ok": self.integrity_ok,
            "assessment_ids": list(self.assessment_ids),
            "assignment_ids": list(self.assignment_ids),
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _report_digest(
            self.system_id, self.posture, self.assessment_count,
            self.assignment_count, self.liable_count,
            self.not_liable_count, self.shared_count,
            self.inconclusive_count, self.not_assessed_count,
            self.assessment_ids, self.assignment_ids)


@dataclass(frozen=True)
class RetireRecord:
    """Terminal record: a system id retired from liability bookkeeping."""
    system_id: str
    reason: str
    seq: int
    digest: str
    schema: str = AI_LIABILITY_SCHEMA
    version: str = AI_LIABILITY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _retire_digest(self.system_id, self.reason)


# ---------------------------------------------------------------------------
# Digest pins
# ---------------------------------------------------------------------------

def _pin(value: Any) -> str:
    return "sha256:" + jcs_sha256_hex(value)


def _assessment_digest(assessment_id: str, system_id: str,
                       liability_kind: str, finding: str, severity: int,
                       assessment_digest: str) -> str:
    return _pin({"assessment_id": assessment_id, "system_id": system_id,
                 "liability_kind": liability_kind, "finding": finding,
                 "severity": severity,
                 "assessment_digest": assessment_digest})


def _assignment_digest(assignment_id: str, assessment_id: str,
                       system_id: str, assignee_kind: str, basis: str,
                       assignment_digest: str) -> str:
    return _pin({"assignment_id": assignment_id,
                 "assessment_id": assessment_id, "system_id": system_id,
                 "assignee_kind": assignee_kind, "basis": basis,
                 "assignment_digest": assignment_digest})


def _verify_digest(record_id: str, verdict: str) -> str:
    return _pin({"record_id": record_id, "verdict": verdict})


def _retire_digest(system_id: str, reason: str) -> str:
    return _pin({"system_id": system_id, "reason": reason})


def _report_digest(system_id: str, posture: str, assessment_count: int,
                   assignment_count: int, liable_count: int,
                   not_liable_count: int, shared_count: int,
                   inconclusive_count: int, not_assessed_count: int,
                   assessment_ids: Tuple[str, ...],
                   assignment_ids: Tuple[str, ...]) -> str:
    return _pin({"system_id": system_id, "posture": posture,
                 "assessment_count": assessment_count,
                 "assignment_count": assignment_count,
                 "liable_count": liable_count,
                 "not_liable_count": not_liable_count,
                 "shared_count": shared_count,
                 "inconclusive_count": inconclusive_count,
                 "not_assessed_count": not_assessed_count,
                 "assessment_ids": list(assessment_ids),
                 "assignment_ids": list(assignment_ids)})


# ---------------------------------------------------------------------------
# Input checks
# ---------------------------------------------------------------------------

def _check_id(value: Any, err: type) -> str:
    if not isinstance(value, str) or not value:
        raise err(f"bad id: {value!r}")
    if len(value) > _MAX_ID_LEN or any(c.isspace() for c in value):
        raise err(f"bad id: {value!r}")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"bad seq: {seq!r}")
    if seq < 0:
        raise SeqOrderError(f"bad seq: {seq!r}")
    return seq


def _check_digest(value: Any) -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"bad digest pin: {value!r}")
    if value != "" and not _DIGEST_RE.match(value):
        raise BadDigestError(f"bad digest pin: {value!r}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError(f"bad severity: {value!r}")
    if value < 0 or value > 100:
        raise BadSeverityError(f"bad severity: {value!r}")
    return value


def ai_liability_audit_event(kind: str, seq: int,
                             **details: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event for the ai-liability ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    _check_seq(seq)
    for key in details:
        if key in _BANNED_DETAIL_KEYS:
            raise AuditKindError(f"audit detail key banned: {key!r}")
    return {
        "kind": kind,
        "audit_seq": seq,
        "schema": AUDIT_SCHEMA,
        "version": AI_LIABILITY_VERSION,
        "detail": dict(details),
    }


def stdlib_only() -> bool:
    """AST self-check: this module imports stdlib modules only."""
    allowed = set(getattr(sys, "stdlib_module_names", ()))
    allowed |= {"canonical_json"}  # the single sanctioned canonicalizer
    # Read own source from the defining file for accuracy.
    path = globals().get("__file__", "")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
    except OSError:
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


# ---------------------------------------------------------------------------
# AILiability
# ---------------------------------------------------------------------------

class AILiability:
    """AI liability decision ledger.

    Declares liability assessments over named AI systems, books declared
    liability assignments (assignee + legal basis), and derives the
    liability posture as data. Deterministic, in-memory, fail-closed;
    no wall-clock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, None] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._assignments: Dict[str, AssignmentRecord] = {}
        self._assessments_for: Dict[str, Tuple[str, ...]] = {}
        self._assignments_for: Dict[str, Tuple[str, ...]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assessment_counter = 0
        self._assignment_counter = 0
        self._last_seq = -1
        self._audit_events: list = []

    # -- internals ---------------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq not increasing: {seq!r}")
        self._last_seq = seq
        return seq

    def _burn(self, seq: int) -> None:
        """Claim the seq even for a failed mutation (claim-then-burn)."""
        self._last_seq = max(self._last_seq, seq)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit_events.append(
            ai_liability_audit_event(kind, seq, **details))

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system retired: {system_id!r}")
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    def _posture(self, assessment_ids: Tuple[str, ...]) -> str:
        """Ledger rule: derive posture as data (never a finding)."""
        findings = [self._assessments[aid].finding for aid in assessment_ids]
        if not findings:
            return POSTURE_UNEVALUATED
        if FINDING_LIABLE in findings or FINDING_SHARED_LIABILITY in findings:
            return POSTURE_LIABILITY_OPEN
        if FINDING_INCONCLUSIVE in findings:
            return POSTURE_CONTESTED
        if FINDING_NOT_ASSESSED in findings:
            return POSTURE_UNASSESSED
        return POSTURE_CLEARED

    def _integrity_ok(self, system_id: str) -> bool:
        """Re-derive all in-scope digest pins as data."""
        for aid in self._assessments_for.get(system_id, ()):
            if not self._assessments[aid].verify():
                return False
        for gid in self._assignments_for.get(system_id, ()):
            if not self._assignments[gid].verify():
                return False
        return True

    # -- mutations ---------------------------------------------------------

    def assess(self, system_id: str, seq: int,
               liability_kind: str = KIND_PRODUCT_LIABILITY,
               finding: str = FINDING_NOT_ASSESSED,
               severity: int = 0,
               assessment_digest: str = "") -> AssessmentRecord:
        """Book one declared liability assessment over a named AI system."""
        with self._lock:
            seq = self._claim(seq)
            try:
                _check_id(system_id, BadSystemError)
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system retired: {system_id!r}")
                if liability_kind not in LIABILITY_KINDS:
                    raise BadLiabilityKindError(
                        f"bad liability kind: {liability_kind!r}")
                if finding not in FINDINGS:
                    raise BadFindingError(f"bad finding: {finding!r}")
                _check_severity(severity)
                _check_digest(assessment_digest)
                if system_id not in self._systems:
                    self._systems[system_id] = None
                    self._assessments_for[system_id] = ()
                    self._assignments_for[system_id] = ()
                self._assessment_counter += 1
                assessment_id = f"asm-{self._assessment_counter}"
                record = AssessmentRecord(
                    assessment_id=assessment_id,
                    system_id=system_id,
                    liability_kind=liability_kind,
                    finding=finding,
                    severity=severity,
                    assessment_digest=assessment_digest,
                    seq=seq,
                    digest=_assessment_digest(
                        assessment_id, system_id, liability_kind,
                        finding, severity, assessment_digest),
                )
            except AILiabilityError as exc:
                self._burn(seq)
                self._emit(KIND_REJECTED, seq,
                           rejected_kind=type(exc).__name__,
                           system_id=system_id)
                raise
            self._assessments[assessment_id] = record
            self._assessments_for[system_id] = (
                self._assessments_for[system_id] + (assessment_id,))
            self._emit(KIND_ASSESSED, seq, assessment_id=assessment_id,
                       system_id=system_id, liability_kind=liability_kind,
                       finding=finding, severity=severity)
            return record

    def assign(self, assessment_id: str, seq: int,
               assignee_kind: str = ASSIGNEE_DEVELOPER,
               basis: str = BASIS_FAULT_BASED,
               assignment_digest: str = "") -> AssignmentRecord:
        """Book one declared liability assignment against an assessment."""
        with self._lock:
            seq = self._claim(seq)
            try:
                _check_id(assessment_id, UnknownAssessmentError)
                if assignee_kind not in ASSIGNEE_KINDS:
                    raise BadAssigneeKindError(
                        f"bad assignee kind: {assignee_kind!r}")
                if basis not in BASES:
                    raise BadBasisError(f"bad basis: {basis!r}")
                _check_digest(assignment_digest)
                try:
                    assessment = self._assessments[assessment_id]
                except KeyError:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}")
                system_id = assessment.system_id
                self._require_live_system(system_id)
                self._assignment_counter += 1
                assignment_id = f"asg-{self._assignment_counter}"
                record = AssignmentRecord(
                    assignment_id=assignment_id,
                    assessment_id=assessment_id,
                    system_id=system_id,
                    assignee_kind=assignee_kind,
                    basis=basis,
                    assignment_digest=assignment_digest,
                    seq=seq,
                    digest=_assignment_digest(
                        assignment_id, assessment_id, system_id,
                        assignee_kind, basis, assignment_digest),
                )
            except AILiabilityError as exc:
                self._burn(seq)
                self._emit(KIND_REJECTED, seq,
                           rejected_kind=type(exc).__name__,
                           assessment_id=assessment_id)
                raise
            self._assignments[assignment_id] = record
            self._assignments_for[system_id] = (
                self._assignments_for[system_id] + (assignment_id,))
            self._emit(KIND_ASSIGNED, seq, assignment_id=assignment_id,
                       assessment_id=assessment_id, system_id=system_id,
                       assignee_kind=assignee_kind, basis=basis)
            return record

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a system id."""
        with self._lock:
            seq = self._claim(seq)
            try:
                _check_id(system_id, BadSystemError)
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system retired: {system_id!r}")
                if system_id not in self._systems:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                record = RetireRecord(
                    system_id=system_id,
                    reason=reason,
                    seq=seq,
                    digest=_retire_digest(system_id, reason),
                )
            except AILiabilityError as exc:
                self._burn(seq)
                self._emit(KIND_REJECTED, seq,
                           rejected_kind=type(exc).__name__,
                           system_id=system_id)
                raise
            self._retired[system_id] = record
            self._emit(KIND_RETIRED, seq, system_id=system_id,
                       reason=reason)
            return record

    # -- pure reads --------------------------------------------------------

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one assessment/assignment digest pin."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(record_id, UnknownAssessmentError)
            record: Optional[Any] = self._assessments.get(record_id)
            if record is None:
                record = self._assignments.get(record_id)
            if record is None:
                raise UnknownAssignmentError(
                    f"unknown record: {record_id!r}")
            ok = record.verify()
            verdict = "verified" if ok else "tampered"
            return VerificationReport(
                record_id=record_id,
                verdict=verdict,
                integrity_ok=ok,
                seq=seq,
                digest=_verify_digest(record_id, verdict),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derived liability posture for one system (data)."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(system_id, BadSystemError)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._scoped_report(seq, system_id)

    def _scoped_report(self, seq: int,
                       system_id: str) -> EvaluationReport:
        assessment_ids = self._assessments_for.get(system_id, ())
        assignment_ids = self._assignments_for.get(system_id, ())
        findings = [self._assessments[aid].finding for aid in assessment_ids]
        posture = self._posture(assessment_ids)
        liable = sum(1 for f in findings if f == FINDING_LIABLE)
        not_liable = sum(1 for f in findings if f == FINDING_NOT_LIABLE)
        shared = sum(1 for f in findings
                     if f == FINDING_SHARED_LIABILITY)
        inconclusive = sum(1 for f in findings
                           if f == FINDING_INCONCLUSIVE)
        not_assessed = sum(1 for f in findings
                           if f == FINDING_NOT_ASSESSED)
        return EvaluationReport(
            system_id=system_id,
            posture=posture,
            assessment_count=len(assessment_ids),
            assignment_count=len(assignment_ids),
            liable_count=liable,
            not_liable_count=not_liable,
            shared_count=shared,
            inconclusive_count=inconclusive,
            not_assessed_count=not_assessed,
            integrity_ok=self._integrity_ok(system_id),
            assessment_ids=assessment_ids,
            assignment_ids=assignment_ids,
            seq=seq,
            digest=_report_digest(
                system_id, posture, len(assessment_ids),
                len(assignment_ids), liable, not_liable, shared,
                inconclusive, not_assessed, assessment_ids,
                assignment_ids),
        )

    # -- views ---------------------------------------------------------------

    def assessment_record(self, assessment_id: str,
                          seq: int) -> AssessmentRecord:
        """Pure read: fetch one booked liability assessment."""
        _check_seq(seq)
        with self._lock:
            _check_id(assessment_id, UnknownAssessmentError)
            try:
                return self._assessments[assessment_id]
            except KeyError:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}")

    def assignment_record(self, assignment_id: str,
                          seq: int) -> AssignmentRecord:
        """Pure read: fetch one booked liability assignment."""
        _check_seq(seq)
        with self._lock:
            _check_id(assignment_id, UnknownAssignmentError)
            try:
                return self._assignments[assignment_id]
            except KeyError:
                raise UnknownAssignmentError(
                    f"unknown assignment: {assignment_id!r}")

    def assessments_for(self, system_id: str,
                        seq: int) -> Tuple[str, ...]:
        """Pure read: assessment ids for one system."""
        _check_seq(seq)
        with self._lock:
            _check_id(system_id, BadSystemError)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._assessments_for.get(system_id, ())

    def assignments_for(self, system_id: str,
                        seq: int) -> Tuple[str, ...]:
        """Pure read: assignment ids for one system."""
        _check_seq(seq)
        with self._lock:
            _check_id(system_id, BadSystemError)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._assignments_for.get(system_id, ())

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all registered system ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._systems.keys())

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all booked assessment ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._assessments.keys())

    def assignment_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all booked assignment ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._assignments.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all retired system ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._retired.keys())

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the audit event stream."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._audit_events)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger tallies."""
        _check_seq(seq)
        with self._lock:
            return {
                "systems": len(self._systems),
                "assessments": len(self._assessments),
                "assignments": len(self._assignments),
                "retired": len(self._retired),
                "audit_events": len(self._audit_events),
                "seq": self._last_seq,
            }


def main() -> None:
    """Self-check: exercise assess/assign/verify/evaluate/retire paths."""
    ledger = AILiability()
    rec = ledger.assess("sys-1", 1,
                        liability_kind=KIND_PRODUCT_LIABILITY,
                        finding=FINDING_LIABLE, severity=80)
    assert rec.assessment_id == "asm-1" and rec.verify()
    asg = ledger.assign("asm-1", 2, assignee_kind=ASSIGNEE_MANUFACTURER,
                        basis=BASIS_STRICT_LIABILITY)
    assert asg.assignment_id == "asg-1" and asg.verify()
    vfy = ledger.verify("asm-1", 3)
    assert vfy.verdict == "verified" and vfy.verify()
    vfy2 = ledger.verify("asg-1", 3)
    assert vfy2.verdict == "verified" and vfy2.verify()
    evl = ledger.evaluate("sys-1", 4)
    assert evl.posture == POSTURE_LIABILITY_OPEN and evl.verify()
    ret = ledger.retire("sys-1", 5, reason=REASON_SETTLED)
    assert ret.verify()
    assert stdlib_only()
    print("ai-liability OK: assess, assign, verify, evaluate, retire, "
          "pins, audit")


if __name__ == "__main__":
    main()
