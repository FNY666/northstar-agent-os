"""AI governance operations decision ledger: declare controls, book audits.

Research motivation: AI governance frameworks (NIST AI RMF Govern,
OECD AI Principles, EU AI Act obligations) all reduce to one
operational bookkeeping shape: a governed AI *system* has declared
*controls* (human oversight, deployment gates, monitoring,
kill-switches), and declared *audits* against those controls with
host-reported findings. This module books that shape as data.

This module is the *operations* half, deliberately distinct from the
sibling layers:

- ``governance.py`` owns the framework *policy* lifecycle
  (adopt policy -> enforce verdicts -> compliance report);
- ``policy_engine.py`` owns rule-level evaluation mechanics;
- ``oversight_board.py`` owns board adjudication;
- this module owns the AI-governance *decision ledger*: which
  governance controls were declared over named AI systems, which
  audit decisions were booked against them, and the resulting
  posture -- all as data, never evidence.

Public API:

- ``AIGovernance.govern(system_id, seq, control_kind=..., status=...,
  control_digest="")`` -- book one declared governance control over
  a named AI system (minted ``ctl-N``). First govern registers the
  system. Control kind comes from the pinned 8-term vocabulary;
  status from the pinned 4-term vocabulary -- both booked *as data*,
  never proof a control exists or works. Raw control evidence never
  enters records: digest pins only.
- ``AIGovernance.audit(system_id, seq, audit_kind=..., finding=...,
  audit_digest="")`` -- book one declared audit decision (minted
  ``adt-N``). Audit kind from the pinned 8-term vocabulary; finding
  from the pinned 4-term vocabulary -- booked *as data*, never proof
  of a real audit. Fail-closed on unknown or retired systems.
- ``AIGovernance.verify(audit_id, seq)`` -- pure read: re-derives
  the digest pin of an audit decision; verdict pinned
  ``verified`` / ``tampered`` as data (tamper reported, never
  raised). Seq shape-validated, never consumed, no audit row.
- ``AIGovernance.report(seq, system_id="")`` -- pure read: derived
  governance posture as data for one system or the whole ledger.
- ``AIGovernance.retire(system_id, seq, reason="manual")`` --
  terminal; the system id is retired forever and later
  govern/audit calls refuse; reads still work; ids never recycled.
- ``ai_governance_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``control-declared`` / ``audited`` / ``retired`` /
  ``rejected``). Raw evidence never crosses the audit boundary:
  ids, pinned vocabulary values, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``control_kind`` must be one of the pinned 8 control kinds.
- ``status`` must be one of the pinned 4 statuses.
- ``audit_kind`` must be one of the pinned 8 audit kinds.
- ``finding`` must be one of the pinned 4 findings.
- digests must be ``sha256:<64hex>`` when supplied.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* governance controls, *host-reported*
  audit findings, and deterministic aggregates. A booked ``pass``
  finding means the host reported a pass -- the module inspected no
  system, ran no audit, and proves nothing about real-world
  governance posture.
- Digest pins prove record integrity, never control effectiveness.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if governance state must survive a restart.
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
AI_GOVERNANCE_VERSION = "ai-governance.v1"

#: Schema pin carried by records and audit events.
AI_GOVERNANCE_SCHEMA = "northstar.ai-governance.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_CONTROL_DECLARED = "control-declared"
KIND_AUDITED = "audited"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_CONTROL_DECLARED, KIND_AUDITED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw evidence never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"evidence", "transcript", "policy", "policy_text", "weights",
     "model", "model_weights", "trace", "log", "payload", "content",
     "raw", "document", "attachment", "report_text", "notes"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned control-kind vocabulary. Labels, not certifications.
CONTROL_HUMAN_OVERSIGHT = "human-oversight"
CONTROL_DEPLOYMENT_GATE = "deployment-gate"
CONTROL_ACCESS_CONTROL = "access-control"
CONTROL_MONITORING = "monitoring"
CONTROL_INCIDENT_RESPONSE = "incident-response"
CONTROL_DOCUMENTATION = "documentation"
CONTROL_RED_TEAMING = "red-teaming"
CONTROL_KILL_SWITCH = "kill-switch"
CONTROL_KINDS = (
    CONTROL_HUMAN_OVERSIGHT,
    CONTROL_DEPLOYMENT_GATE,
    CONTROL_ACCESS_CONTROL,
    CONTROL_MONITORING,
    CONTROL_INCIDENT_RESPONSE,
    CONTROL_DOCUMENTATION,
    CONTROL_RED_TEAMING,
    CONTROL_KILL_SWITCH,
)

#: Pinned control-status vocabulary. Host-reported data, never proof.
STATUS_SATISFIED = "satisfied"
STATUS_GAP = "gap"
STATUS_WAIVER = "waiver"
STATUS_NOT_ASSESSED = "not-assessed"
STATUSES = (STATUS_SATISFIED, STATUS_GAP, STATUS_WAIVER,
            STATUS_NOT_ASSESSED)

#: Pinned audit-kind vocabulary.
AUDIT_COMPLIANCE_REVIEW = "compliance-review"
AUDIT_READINESS_ASSESSMENT = "readiness-assessment"
AUDIT_MODEL_AUDIT = "model-audit"
AUDIT_DATA_AUDIT = "data-audit"
AUDIT_INCIDENT_REVIEW = "incident-review"
AUDIT_CHANGE_REVIEW = "change-review"
AUDIT_RED_TEAM_ASSESSMENT = "red-team-assessment"
AUDIT_POST_DEPLOYMENT_REVIEW = "post-deployment-review"
AUDIT_KINDS = (
    AUDIT_COMPLIANCE_REVIEW,
    AUDIT_READINESS_ASSESSMENT,
    AUDIT_MODEL_AUDIT,
    AUDIT_DATA_AUDIT,
    AUDIT_INCIDENT_REVIEW,
    AUDIT_CHANGE_REVIEW,
    AUDIT_RED_TEAM_ASSESSMENT,
    AUDIT_POST_DEPLOYMENT_REVIEW,
)

#: Pinned finding vocabulary. Findings are host-reported data.
FINDING_PASS = "pass"
FINDING_FAIL = "fail"
FINDING_PARTIAL = "partial"
FINDING_INCONCLUSIVE = "inconclusive"
FINDINGS = (FINDING_PASS, FINDING_FAIL, FINDING_PARTIAL,
            FINDING_INCONCLUSIVE)

#: Pinned retire-reason vocabulary.
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_DECOMMISSIONED = "decommissioned"
RETIRE_REASONS = (REASON_MANUAL, REASON_SUPERSEDED,
                  REASON_DECOMMISSIONED)

#: Regex for a well-formed sha256 digest pin.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AIGovernanceError(Exception):
    """Base error for the ai-governance module."""


class BadSystemError(AIGovernanceError):
    """Malformed system id."""


class UnknownSystemError(AIGovernanceError):
    """System id not governed."""


class RetiredSystemError(AIGovernanceError):
    """System id was retired; never recycled."""


class BadControlKindError(AIGovernanceError):
    """Control kind outside the pinned vocabulary."""


class BadStatusError(AIGovernanceError):
    """Control status outside the pinned vocabulary."""


class BadAuditKindError(AIGovernanceError):
    """Audit kind outside the pinned vocabulary."""


class BadFindingError(AIGovernanceError):
    """Finding outside the pinned vocabulary."""


class BadDigestError(AIGovernanceError):
    """Malformed sha256 digest pin."""


class BadReasonError(AIGovernanceError):
    """Retire reason outside the pinned vocabulary."""


class UnknownAuditError(AIGovernanceError):
    """Audit id not booked."""


class SeqOrderError(AIGovernanceError):
    """Seq not a strictly increasing int."""


class AuditKindError(AIGovernanceError):
    """Audit kind outside the pinned vocabulary or banned detail key."""


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlRecord:
    """One declared governance control over a named AI system."""
    control_id: str
    system_id: str
    control_kind: str
    status: str
    control_digest: str
    seq: int
    digest: str
    schema: str = AI_GOVERNANCE_SCHEMA
    version: str = AI_GOVERNANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "system_id": self.system_id,
            "control_kind": self.control_kind,
            "status": self.status,
            "control_digest": self.control_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        """Recompute the tamper-evident pin."""
        return self.digest == _control_digest(
            self.control_id, self.system_id, self.control_kind,
            self.status, self.control_digest)


@dataclass(frozen=True)
class AuditDecisionRecord:
    """One declared audit decision against a governed system."""
    audit_id: str
    system_id: str
    audit_kind: str
    finding: str
    audit_digest: str
    seq: int
    digest: str
    schema: str = AI_GOVERNANCE_SCHEMA
    version: str = AI_GOVERNANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "system_id": self.system_id,
            "audit_kind": self.audit_kind,
            "finding": self.finding,
            "audit_digest": self.audit_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _audit_digest(
            self.audit_id, self.system_id, self.audit_kind,
            self.finding, self.audit_digest)


@dataclass(frozen=True)
class VerificationReport:
    """Pure read view of one audit decision's integrity (data, not proof)."""
    audit_id: str
    verdict: str  # "verified" | "tampered"
    integrity_ok: bool
    seq: int
    digest: str
    schema: str = AI_GOVERNANCE_SCHEMA
    version: str = AI_GOVERNANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _verify_digest(self.audit_id, self.verdict)


@dataclass(frozen=True)
class GovernancePostureReport:
    """Pure read view of derived governance posture (data, not findings)."""
    system_id: str  # "" for whole-ledger scope
    posture: str  # "unaudited" | "non-compliant" | "inconclusive"
                  # | "partial" | "compliant"
    control_count: int
    audit_count: int
    gap_count: int
    fail_count: int
    pass_count: int
    integrity_ok: bool
    audit_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = AI_GOVERNANCE_SCHEMA
    version: str = AI_GOVERNANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "posture": self.posture,
            "control_count": self.control_count,
            "audit_count": self.audit_count,
            "gap_count": self.gap_count,
            "fail_count": self.fail_count,
            "pass_count": self.pass_count,
            "integrity_ok": self.integrity_ok,
            "audit_ids": list(self.audit_ids),
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _report_digest(
            self.system_id, self.posture, self.control_count,
            self.audit_count, self.gap_count, self.fail_count,
            self.pass_count, self.audit_ids)


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a system id."""
    system_id: str
    reason: str
    seq: int
    digest: str
    schema: str = AI_GOVERNANCE_SCHEMA
    version: str = AI_GOVERNANCE_VERSION

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


def _control_digest(control_id: str, system_id: str, control_kind: str,
                    status: str, control_digest: str) -> str:
    return _pin({"control_id": control_id, "system_id": system_id,
                 "control_kind": control_kind, "status": status,
                 "control_digest": control_digest})


def _audit_digest(audit_id: str, system_id: str, audit_kind: str,
                  finding: str, audit_digest: str) -> str:
    return _pin({"audit_id": audit_id, "system_id": system_id,
                 "audit_kind": audit_kind, "finding": finding,
                 "audit_digest": audit_digest})


def _verify_digest(audit_id: str, verdict: str) -> str:
    return _pin({"audit_id": audit_id, "verdict": verdict})


def _retire_digest(system_id: str, reason: str) -> str:
    return _pin({"system_id": system_id, "reason": reason})


def _report_digest(system_id: str, posture: str, control_count: int,
                   audit_count: int, gap_count: int, fail_count: int,
                   pass_count: int, audit_ids: Tuple[str, ...]) -> str:
    return _pin({"system_id": system_id, "posture": posture,
                 "control_count": control_count, "audit_count": audit_count,
                 "gap_count": gap_count, "fail_count": fail_count,
                 "pass_count": pass_count,
                 "audit_ids": sorted(audit_ids)})


# ---------------------------------------------------------------------------
# Validation helpers
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


def ai_governance_audit_event(kind: str, seq: int,
                             **details: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event for the ai-governance ledger."""
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
        "version": AI_GOVERNANCE_VERSION,
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
# AIGovernance
# ---------------------------------------------------------------------------

class AIGovernance:
    """AI governance operations decision ledger.

    Declares governance controls over named AI systems, books declared
    audit decisions against them, and derives posture as data.
    Deterministic, in-memory, fail-closed; no wall-clock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, None] = {}
        self._controls: Dict[str, ControlRecord] = {}
        self._controls_for: Dict[str, Tuple[str, ...]] = {}
        self._audits: Dict[str, AuditDecisionRecord] = {}
        self._audits_for: Dict[str, Tuple[str, ...]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._control_counter = 0
        self._audit_counter = 0
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
            ai_governance_audit_event(kind, seq, **details))

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system retired: {system_id!r}")
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    def _posture(self, audit_ids: Tuple[str, ...]) -> str:
        """Derive posture from booked findings (data, never findings)."""
        if not audit_ids:
            return "unaudited"
        findings = [self._audits[aid].finding for aid in audit_ids]
        if FINDING_FAIL in findings:
            return "non-compliant"
        if FINDING_INCONCLUSIVE in findings:
            return "inconclusive"
        if FINDING_PARTIAL in findings:
            return "partial"
        return "compliant"

    def _integrity_ok(self, system_id: str) -> bool:
        for cid in self._controls_for.get(system_id, ()):
            if not self._controls[cid].verify():
                return False
        for aid in self._audits_for.get(system_id, ()):
            if not self._audits[aid].verify():
                return False
        return True

    # -- public API ---------------------------------------------------------

    def govern(self, system_id: str, seq: int,
               control_kind: str = CONTROL_HUMAN_OVERSIGHT,
               status: str = STATUS_NOT_ASSESSED,
               control_digest: str = "") -> ControlRecord:
        """Declare one governance control over a named AI system."""
        seq = self._claim(seq)
        try:
            _check_id(system_id, BadSystemError)
            if system_id in self._retired:
                raise RetiredSystemError(
                    f"system retired: {system_id!r}")
            if control_kind not in CONTROL_KINDS:
                raise BadControlKindError(
                    f"bad control kind: {control_kind!r}")
            if status not in STATUSES:
                raise BadStatusError(f"bad status: {status!r}")
            _check_digest(control_digest)
            if system_id not in self._systems:
                self._systems[system_id] = None
                self._controls_for[system_id] = ()
                self._audits_for[system_id] = ()
            self._control_counter += 1
            control_id = f"ctl-{self._control_counter}"
            record = ControlRecord(
                control_id=control_id,
                system_id=system_id,
                control_kind=control_kind,
                status=status,
                control_digest=control_digest,
                seq=seq,
                digest=_control_digest(control_id, system_id, control_kind,
                                       status, control_digest),
            )
        except AIGovernanceError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._controls[control_id] = record
        self._controls_for[system_id] = (
            self._controls_for[system_id] + (control_id,))
        self._emit(KIND_CONTROL_DECLARED, seq, control_id=control_id,
                   system_id=system_id, control_kind=control_kind,
                   status=status)
        return record

    def audit(self, system_id: str, seq: int,
              audit_kind: str = AUDIT_COMPLIANCE_REVIEW,
              finding: str = FINDING_PASS,
              audit_digest: str = "") -> AuditDecisionRecord:
        """Book one declared audit decision against a governed system."""
        seq = self._claim(seq)
        try:
            _check_id(system_id, BadSystemError)
            self._require_live_system(system_id)
            if audit_kind not in AUDIT_KINDS:
                raise BadAuditKindError(
                    f"bad audit kind: {audit_kind!r}")
            if finding not in FINDINGS:
                raise BadFindingError(f"bad finding: {finding!r}")
            _check_digest(audit_digest)
            self._audit_counter += 1
            audit_id = f"adt-{self._audit_counter}"
            record = AuditDecisionRecord(
                audit_id=audit_id,
                system_id=system_id,
                audit_kind=audit_kind,
                finding=finding,
                audit_digest=audit_digest,
                seq=seq,
                digest=_audit_digest(audit_id, system_id, audit_kind,
                                     finding, audit_digest),
            )
        except AIGovernanceError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._audits[audit_id] = record
        self._audits_for[system_id] = (
            self._audits_for[system_id] + (audit_id,))
        self._emit(KIND_AUDITED, seq, audit_id=audit_id,
                   system_id=system_id, audit_kind=audit_kind,
                   finding=finding)
        return record

    def verify(self, audit_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one audit decision's digest pin."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(audit_id, UnknownAuditError)
            try:
                record = self._audits[audit_id]
            except KeyError:
                raise UnknownAuditError(f"unknown audit: {audit_id!r}")
            ok = record.verify()
            verdict = "verified" if ok else "tampered"
            return VerificationReport(
                audit_id=audit_id,
                verdict=verdict,
                integrity_ok=ok,
                seq=seq,
                digest=_verify_digest(audit_id, verdict),
            )

    def report(self, seq: int, system_id: str = "") -> GovernancePostureReport:
        """Pure read: derived governance posture (data, never findings)."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            if system_id:
                _check_id(system_id, BadSystemError)
                if system_id not in self._systems:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                control_ids = self._controls_for.get(system_id, ())
                audit_ids = self._audits_for.get(system_id, ())
            else:
                control_ids = tuple(self._controls.keys())
                audit_ids = tuple(self._audits.keys())
            gap_count = sum(
                1 for cid in control_ids
                if self._controls[cid].status == STATUS_GAP)
            findings = [self._audits[aid].finding for aid in audit_ids]
            fail_count = sum(1 for f in findings if f == FINDING_FAIL)
            pass_count = sum(1 for f in findings if f == FINDING_PASS)
            integrity = all(
                self._integrity_ok(sid)
                for sid in (self._systems if not system_id
                            else (system_id,)))
            return GovernancePostureReport(
                system_id=system_id,
                posture=self._posture(audit_ids),
                control_count=len(control_ids),
                audit_count=len(audit_ids),
                gap_count=gap_count,
                fail_count=fail_count,
                pass_count=pass_count,
                integrity_ok=integrity,
                audit_ids=audit_ids,
                seq=seq,
                digest=_report_digest(system_id, self._posture(audit_ids),
                                      len(control_ids), len(audit_ids),
                                      gap_count, fail_count, pass_count,
                                      audit_ids),
            )

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a system id."""
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
        except AIGovernanceError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._retired[system_id] = record
        self._emit(KIND_RETIRED, seq, system_id=system_id, reason=reason)
        return record

    # -- pure-read views -----------------------------------------------------

    def control_record(self, control_id: str, seq: int) -> ControlRecord:
        """Pure read: fetch one control record (no audit row)."""
        _check_seq(seq)
        try:
            return self._controls[control_id]
        except KeyError:
            raise UnknownSystemError(
                f"unknown control: {control_id!r}")

    def audit_record(self, audit_id: str, seq: int) -> AuditDecisionRecord:
        """Pure read: fetch one audit decision record (no audit row)."""
        _check_seq(seq)
        try:
            return self._audits[audit_id]
        except KeyError:
            raise UnknownAuditError(f"unknown audit: {audit_id!r}")

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: governed system ids (no audit row)."""
        _check_seq(seq)
        return tuple(self._systems.keys())

    def controls_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read: control ids for one system (no audit row)."""
        _check_seq(seq)
        _check_id(system_id, BadSystemError)
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        return self._controls_for.get(system_id, ())

    def audits_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read: audit ids for one system (no audit row)."""
        _check_seq(seq)
        _check_id(system_id, BadSystemError)
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        return self._audits_for.get(system_id, ())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: retired system ids (no audit row)."""
        _check_seq(seq)
        return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters (no audit row)."""
        _check_seq(seq)
        return {
            "systems": len(self._systems),
            "controls": len(self._controls),
            "audits": len(self._audits),
            "retired": len(self._retired),
            "seq": self._last_seq,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the booked audit.ndjson/1 rows (no audit row)."""
        _check_seq(seq)
        return tuple(self._audit_events)


def main() -> None:
    """Self-check: exercise govern/audit/verify/retire/report paths."""
    g = AIGovernance()
    ctl = g.govern("sys-1", 1, control_kind=CONTROL_KILL_SWITCH,
                   status=STATUS_SATISFIED)
    assert ctl.control_id == "ctl-1" and ctl.verify()
    adt = g.audit("sys-1", 2, audit_kind=AUDIT_MODEL_AUDIT,
                  finding=FINDING_PASS)
    assert adt.audit_id == "adt-1" and adt.verify()
    rep = g.report(3, "sys-1")
    assert rep.posture == "compliant" and rep.verify()
    vfy = g.verify("adt-1", 4)
    assert vfy.verdict == "verified" and vfy.verify()
    ret = g.retire("sys-1", 5)
    assert ret.verify()
    assert stdlib_only()
    print("ai-governance OK: govern, audit, verify, report, retire, pins, audit")


if __name__ == "__main__":
    main()
