"""Audit-engagement management decision ledger: plan, execute, followup.

Research context: governance / compliance audit programs (SOC 2 / ISO 27001 /
PCI DSS / HIPAA / vendor-assessment shaped) run a lifecycle: an audit is
*planned* (standard, scope, auditee, period), then *executed* (evidence is
reviewed and an outcome is booked), then *followed up* (findings are
remediated, risks accepted, or escalation declared). The raw material -- audit
evidence, finding narratives, interview transcripts, system snapshots -- must
never enter the ledger or the audit trail.

This module is the *decision ledger* layer for that lifecycle. It owns the
plan -> execute -> followup flow as a deterministic, digest-pinned state
machine with caller-int seq discipline and an audit trail. It performs no
audit procedure, inspects no evidence, interviews nobody, and certifies
nothing; it books the host's *declared* decisions in a tamper-evident,
seq-ordered form.

What each operation means:

1. ``plan(audit_id, seq, standard=..., scope_digest="", auditee_digest="",
   period_digest="")`` -- books one *declared* audit engagement plan over the
   pinned standard vocabulary (``soc2-type1`` / ``soc2-type2`` /
   ``iso27001`` / ``pci-dss`` / ``hipaa`` / ``internal`` / ``vendor``). Scope,
   auditee, and period travel as ``sha256:`` digest pins only: raw scope
   descriptions, system names, and date ranges never enter a record.
   Duplicate ids refused fail-closed.
2. ``execute(audit_id, seq, outcome, evidence_digest="")`` -- books one
   declared execution result, minted as ``exe-N``. The outcome is pinned to
   ``clean`` / ``findings`` / ``opportunity`` / ``qualified`` and booked
   **as data** (a host declaration, never proof an audit was performed well).
   Evidence travels as a digest pin only. One execution per audit; a second
   is refused fail-closed.
3. ``followup(audit_id, seq, action, action_digest="")`` -- books one declared
   follow-up action, minted as ``fup-N``, over the pinned action vocabulary
   (``remediated`` / ``accepted-risk`` / ``escalated`` / ``re-audited`` /
   ``deferred``). Requires a prior execution (fail-closed). Repeatable as an
   action chain: remediate, re-audit, defer -- each step booked separately.
4. ``status(audit_id, seq)`` -- pure read view: plan, execution, follow-up
   chain state of one engagement plus re-derived digest integrity as data.

Distinct-layer rationale: the tree already has ``audit_chain.py``
(tamper-evident hash chain), ``audit_export.py`` (export format),
``audit_compaction.py`` (retention), ``audit_archive.py`` (archival),
``audit_merkle.py`` (merkle anchoring), ``audit_rekor.py`` / ``audit_scitt.py``
(transparency-log mirrors), ``audit_shipper.py`` (shipping), and
``audit_committee.py`` (committee-role governance). Per the additive sibling
pattern, this module is the *engagement-management* layer none of them own:
who audits what, under which standard, what was declared, and what happened
next.

Honest scope: a booked ``clean`` outcome means "the host declared this
engagement clean at this seq", never that controls are actually effective.
A booked ``remediated`` action means "the host declared remediation", never
that the finding is truly gone. Declarations are GIGO host claims.

House style: frozen dataclasses, caller int seqs strictly increasing
(claim-then-burn: failed mutations consume their seq and book
``audit-management.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only (with the sibling
``canonical_json`` try/except fallback), ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
AUDIT_MANAGEMENT_VERSION = "audit-management.v1"

#: Schema pin carried by records and audit events.
AUDIT_MANAGEMENT_SCHEMA = "northstar.audit-management.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Declared audit-standard vocabulary (booked as data).
STANDARDS = (
    "soc2-type1",
    "soc2-type2",
    "iso27001",
    "pci-dss",
    "hipaa",
    "internal",
    "vendor",
)

#: Declared execution-outcome vocabulary (booked as data).
OUTCOMES = ("clean", "findings", "opportunity", "qualified")

#: Declared follow-up action vocabulary (booked as data).
ACTIONS = ("remediated", "accepted-risk", "escalated", "re-audited", "deferred")

#: Audit kinds for this module (append-only vocabulary).
KIND_PLANNED = "audit-management.planned"
KIND_EXECUTED = "audit-management.executed"
KIND_FOLLOWED_UP = "audit-management.followed-up"
KIND_REJECTED = "audit-management.rejected"
_KINDS = (KIND_PLANNED, KIND_EXECUTED, KIND_FOLLOWED_UP, KIND_REJECTED)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AuditManagementError(Exception):
    """Base class for all audit-management ledger failures."""


class BadIdError(AuditManagementError):
    """Audit id is malformed."""


class DuplicateAuditError(AuditManagementError):
    """An audit id is already booked."""


class UnknownAuditError(AuditManagementError):
    """No audit is booked under this id."""


class BadDigestError(AuditManagementError):
    """A digest pin is not a valid sha256: pin (or empty)."""


class BadStandardError(AuditManagementError):
    """Standard is not in the pinned vocabulary."""


class BadOutcomeError(AuditManagementError):
    """Outcome is not in the pinned vocabulary."""


class BadActionError(AuditManagementError):
    """Follow-up action is not in the pinned vocabulary."""


class AlreadyExecutedError(AuditManagementError):
    """An audit that already has an execution cannot be executed again."""


class NotExecutedError(AuditManagementError):
    """A follow-up requires a prior execution."""


class SeqOrderError(AuditManagementError):
    """Seq is malformed or not strictly increasing."""


class AuditKindError(AuditManagementError):
    """Unknown audit kind or banned key in audit detail."""


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq <= 0:
        raise SeqOrderError(f"seq must be positive, got {seq}")
    return seq


def _check_id(value: Any, name: str = "audit_id") -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{name} must be a non-empty str (<=128 chars)")
    if value != value.strip() or any(c.isspace() for c in value):
        raise BadIdError(f"{name} must not contain whitespace")
    return value


def _check_optional_digest(value: Any, name: str) -> str:
    """Digest pin or '' (content pins never required at plan time)."""
    if value == "":
        return ""
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != len("sha256:") + 64
    ):
        raise BadDigestError(f"{name} must be '' or a 'sha256:<64hex>' pin")
    try:
        int(value[len("sha256:"):], 16)
    except ValueError:
        raise BadDigestError(f"{name} must be '' or a 'sha256:<64hex>' pin")
    return value


def _check_standard(value: Any) -> str:
    if not isinstance(value, str) or value not in STANDARDS:
        raise BadStandardError(f"standard must be one of {STANDARDS}")
    return value


def _check_outcome(value: Any) -> str:
    if not isinstance(value, str) or value not in OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {OUTCOMES}")
    return value


def _check_action(value: Any) -> str:
    if not isinstance(value, str) or value not in ACTIONS:
        raise BadActionError(f"action must be one of {ACTIONS}")
    return value


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        try:
            return _cj.jcs_dumps(obj).encode("utf-8")
        except Exception:
            pass
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], domain: str) -> str:
    h = hashlib.sha256()
    h.update(b"northstar.audit-management:")
    h.update(domain.encode("utf-8"))
    h.update(b":")
    h.update(_canonical(parts))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def audit_management_audit_event(audit_kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw audit material never crosses this boundary."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    banned = (
        "report",
        "finding",
        "evidence",
        "content",
        "text",
        "payload",
        "notes",
        "scope",
        "plan",
        "auditee",
        "secret",
        "raw",
        "private",
        "transcript",
        "period",
    )
    for key in detail:
        if key in banned:
            raise AuditKindError(f"banned key in audit detail: {key!r}")
    event = {
        "schema": AUDIT_SCHEMA,
        "module": AUDIT_MANAGEMENT_SCHEMA,
        "kind": audit_kind,
        "seq": _check_seq(seq),
        "detail": dict(detail),
    }
    return event


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditPlan:
    """One booked audit engagement plan."""

    audit_id: str
    standard: str
    scope_digest: str
    auditee_digest: str
    period_digest: str
    seq: int
    digest: str
    schema: str = AUDIT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.audit_id,
                self.standard,
                self.scope_digest,
                self.auditee_digest,
                self.period_digest,
                self.seq,
            ),
            "plan",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": AUDIT_MANAGEMENT_VERSION,
            "audit_id": self.audit_id,
            "standard": self.standard,
            "scope_digest": self.scope_digest,
            "auditee_digest": self.auditee_digest,
            "period_digest": self.period_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ExecutionRecord:
    """One booked execution result (minted exe-N)."""

    execution_id: str
    audit_id: str
    outcome: str
    evidence_digest: str
    seq: int
    digest: str
    schema: str = AUDIT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.execution_id, self.audit_id, self.outcome, self.evidence_digest, self.seq),
            "execute",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": AUDIT_MANAGEMENT_VERSION,
            "execution_id": self.execution_id,
            "audit_id": self.audit_id,
            "outcome": self.outcome,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class FollowupRecord:
    """One booked follow-up action (minted fup-N)."""

    followup_id: str
    audit_id: str
    action: str
    action_digest: str
    seq: int
    digest: str
    schema: str = AUDIT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.followup_id, self.audit_id, self.action, self.action_digest, self.seq),
            "followup",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": AUDIT_MANAGEMENT_VERSION,
            "followup_id": self.followup_id,
            "audit_id": self.audit_id,
            "action": self.action,
            "action_digest": self.action_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class EngagementStatus:
    """Pure read view of one engagement's lifecycle state."""

    audit_id: str
    planned: bool
    standard: str
    executed: bool
    outcome: str
    followups: int
    last_action: str
    integrity_ok: bool
    digest: str
    schema: str = AUDIT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.audit_id,
                self.planned,
                self.standard,
                self.executed,
                self.outcome,
                self.followups,
                self.last_action,
            ),
            "status",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": AUDIT_MANAGEMENT_VERSION,
            "audit_id": self.audit_id,
            "planned": self.planned,
            "standard": self.standard,
            "executed": self.executed,
            "outcome": self.outcome,
            "followups": self.followups,
            "last_action": self.last_action,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class AuditManagement:
    """Audit-engagement plan -> execute -> followup decision ledger.

    Deterministic single-host state machine: frozen records, caller-int
    seqs strictly increasing (claim-then-burn), RLock-guarded, fail-closed,
    no wall-clock, stdlib-only. Booked plans, outcomes, and follow-ups are
    host declarations, never proof an audit was performed or completed.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._plans: Dict[str, AuditPlan] = {}
        self._executions: Dict[str, ExecutionRecord] = {}
        self._execution_by_audit: Dict[str, str] = {}
        self._followups: Dict[str, FollowupRecord] = {}
        self._followups_by_audit: Dict[str, List[str]] = {}
        self._n_execution = 0
        self._n_followup = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ----------------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(audit_management_audit_event(audit_kind, seq, **detail))

    # -- mutations ----------------------------------------------------------

    def plan(
        self,
        audit_id: Any,
        seq: Any,
        standard: Any = "soc2-type2",
        scope_digest: Any = "",
        auditee_digest: Any = "",
        period_digest: Any = "",
    ) -> AuditPlan:
        """Book one audit engagement plan. Scope material travels as digest pins only."""
        with self._lock:
            seq = self._claim(seq)  # claim first: failures burn the seq
            try:
                aid = _check_id(audit_id)
                std = _check_standard(standard)
                sdig = _check_optional_digest(scope_digest, "scope_digest")
                adig = _check_optional_digest(auditee_digest, "auditee_digest")
                pdig = _check_optional_digest(period_digest, "period_digest")
                if aid in self._plans:
                    raise DuplicateAuditError(f"audit already booked: {aid!r}")
                digest = _digest_pin((aid, std, sdig, adig, pdig, seq), "plan")
                record = AuditPlan(
                    audit_id=aid,
                    standard=std,
                    scope_digest=sdig,
                    auditee_digest=adig,
                    period_digest=pdig,
                    seq=seq,
                    digest=digest,
                )
            except AuditManagementError:
                self._emit(KIND_REJECTED, seq, op="plan")
                raise
            self._plans[aid] = record
            self._emit(
                KIND_PLANNED,
                seq,
                audit_id=aid,
                standard=std,
                scope_digest=sdig,
                auditee_digest=adig,
                period_digest=pdig,
            )
            return record

    def execute(self, audit_id: Any, seq: Any, outcome: Any, evidence_digest: Any = "") -> ExecutionRecord:
        """Book one execution result for a planned audit (one-shot)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                aid = _check_id(audit_id)
                out = _check_outcome(outcome)
                edig = _check_optional_digest(evidence_digest, "evidence_digest")
                if aid not in self._plans:
                    raise UnknownAuditError(f"unknown audit: {aid!r}")
                if aid in self._execution_by_audit:
                    raise AlreadyExecutedError(f"audit already executed: {aid!r}")
                self._n_execution += 1
                eid = f"exe-{self._n_execution}"
                digest = _digest_pin((eid, aid, out, edig, seq), "execute")
                record = ExecutionRecord(
                    execution_id=eid,
                    audit_id=aid,
                    outcome=out,
                    evidence_digest=edig,
                    seq=seq,
                    digest=digest,
                )
            except AuditManagementError:
                self._emit(KIND_REJECTED, seq, op="execute")
                raise
            self._executions[eid] = record
            self._execution_by_audit[aid] = eid
            self._emit(
                KIND_EXECUTED, seq, execution_id=eid, audit_id=aid, outcome=out,
                evidence_digest=edig,
            )
            return record

    def followup(self, audit_id: Any, seq: Any, action: Any, action_digest: Any = "") -> FollowupRecord:
        """Book one follow-up action for an executed audit (repeatable chain)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                aid = _check_id(audit_id)
                act = _check_action(action)
                adig = _check_optional_digest(action_digest, "action_digest")
                if aid not in self._plans:
                    raise UnknownAuditError(f"unknown audit: {aid!r}")
                if aid not in self._execution_by_audit:
                    raise NotExecutedError(f"audit has no execution: {aid!r}")
                self._n_followup += 1
                fid = f"fup-{self._n_followup}"
                digest = _digest_pin((fid, aid, act, adig, seq), "followup")
                record = FollowupRecord(
                    followup_id=fid,
                    audit_id=aid,
                    action=act,
                    action_digest=adig,
                    seq=seq,
                    digest=digest,
                )
            except AuditManagementError:
                self._emit(KIND_REJECTED, seq, op="followup")
                raise
            self._followups[fid] = record
            self._followups_by_audit.setdefault(aid, []).append(fid)
            self._emit(
                KIND_FOLLOWED_UP, seq, followup_id=fid, audit_id=aid, action=act,
                action_digest=adig,
            )
            return record

    # -- pure reads ---------------------------------------------------------

    def _read_seq(self, seq: Any) -> int:
        return _check_seq(seq)

    def plan_record(self, audit_id: Any, seq: Any) -> AuditPlan:
        with self._lock:
            self._read_seq(seq)
            aid = _check_id(audit_id)
            if aid not in self._plans:
                raise UnknownAuditError(f"unknown audit: {aid!r}")
            return self._plans[aid]

    def execution_record(self, audit_id: Any, seq: Any) -> ExecutionRecord:
        with self._lock:
            self._read_seq(seq)
            aid = _check_id(audit_id)
            eid = self._execution_by_audit.get(aid)
            if eid is None:
                raise UnknownAuditError(f"no execution booked for audit: {aid!r}")
            return self._executions[eid]

    def followup_record(self, followup_id: Any, seq: Any) -> FollowupRecord:
        with self._lock:
            self._read_seq(seq)
            fid = _check_id(followup_id, "followup_id")
            if fid not in self._followups:
                raise UnknownAuditError(f"unknown followup: {fid!r}")
            return self._followups[fid]

    def followups_for(self, audit_id: Any, seq: Any) -> Tuple[FollowupRecord, ...]:
        with self._lock:
            self._read_seq(seq)
            aid = _check_id(audit_id)
            return tuple(self._followups[fid] for fid in self._followups_by_audit.get(aid, ()))

    def audit_ids(self, seq: Any) -> Tuple[str, ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(self._plans))

    def executed_ids(self, seq: Any) -> Tuple[str, ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(self._execution_by_audit))

    def pending_ids(self, seq: Any) -> Tuple[str, ...]:
        """Planned audits with no execution booked yet."""
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(a for a in self._plans if a not in self._execution_by_audit))

    def open_findings_ids(self, seq: Any) -> Tuple[str, ...]:
        """Audits with an execution but no follow-up booked yet."""
        with self._lock:
            self._read_seq(seq)
            return tuple(
                sorted(
                    a
                    for a in self._execution_by_audit
                    if not self._followups_by_audit.get(a)
                )
            )

    def status(self, audit_id: Any, seq: Any) -> EngagementStatus:
        """Pure read view of one engagement's lifecycle state (seq never consumed)."""
        with self._lock:
            self._read_seq(seq)
            aid = _check_id(audit_id)
            plan = self._plans.get(aid)
            if plan is None:
                raise UnknownAuditError(f"unknown audit: {aid!r}")
            eid = self._execution_by_audit.get(aid)
            exe = self._executions.get(eid) if eid else None
            fups = self._followups_by_audit.get(aid, ())
            outcome = exe.outcome if exe else ""
            last_action = self._followups[fups[-1]].action if fups else ""
            integrity = plan.verify()
            if exe is not None:
                integrity = integrity and exe.verify()
            for fid in fups:
                integrity = integrity and self._followups[fid].verify()
            digest = _digest_pin(
                (aid, True, plan.standard, exe is not None, outcome, len(fups), last_action),
                "status",
            )
            return EngagementStatus(
                audit_id=aid,
                planned=True,
                standard=plan.standard,
                executed=exe is not None,
                outcome=outcome,
                followups=len(fups),
                last_action=last_action,
                integrity_ok=integrity,
                digest=digest,
            )

    def stats(self, seq: Any) -> Dict[str, Any]:
        with self._lock:
            self._read_seq(seq)
            outcome_tally: Dict[str, int] = {o: 0 for o in OUTCOMES}
            for exe in self._executions.values():
                outcome_tally[exe.outcome] += 1
            action_tally: Dict[str, int] = {a: 0 for a in ACTIONS}
            for fup in self._followups.values():
                action_tally[fup.action] += 1
            return {
                "schema": AUDIT_MANAGEMENT_SCHEMA,
                "planned": len(self._plans),
                "executed": len(self._execution_by_audit),
                "followups": len(self._followups),
                "pending": len(self._plans) - len(self._execution_by_audit),
                "open_findings": sum(
                    1
                    for a in self._execution_by_audit
                    if not self._followups_by_audit.get(a)
                ),
                "outcomes": outcome_tally,
                "actions": action_tally,
                "rejected_rows": sum(1 for e in self._audit if e["kind"] == KIND_REJECTED),
            }

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(self._audit)


def main() -> None:
    ledger = AuditManagement()
    digest = "sha256:" + "ab" * 32
    plan = ledger.plan("aud-1", 1, standard="iso27001", scope_digest=digest,
                      auditee_digest=digest, period_digest=digest)
    assert plan.verify()
    exe = ledger.execute("aud-1", 2, "findings", evidence_digest=digest)
    assert exe.verify() and exe.execution_id == "exe-1"
    fup = ledger.followup("aud-1", 3, "remediated", action_digest=digest)
    assert fup.verify() and fup.followup_id == "fup-1"
    fup2 = ledger.followup("aud-1", 4, "re-audited")
    assert fup2.verify() and fup2.followup_id == "fup-2"
    st = ledger.status("aud-1", 5)
    assert st.verify() and st.integrity_ok
    assert st.followups == 2 and st.last_action == "re-audited"
    assert st.outcome == "findings"
    print("audit-management OK: plan, execute, followup, status, pins, audit")


if __name__ == "__main__":
    main()
