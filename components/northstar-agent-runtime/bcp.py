"""Business continuity plan (BCP) governance ledger.

Distinct from siblings: ``disaster_recovery`` owns the *technical* DR
ledger - failover/failback events with RPO/RTO accounting and DR drill
kinds (tabletop/game-day/failover-simulation/restore-test); and
``account_recovery`` owns account-level recovery flows. This module is
the *organizational* continuity-plan lifecycle none of them owns: it
books declared continuity plans over business-function scopes, declared
BCP exercises (the classic exercise taxonomy: walkthrough / simulation /
parallel / full-interruption / checklist), and declared plan
*activations* - the organizational decision "we invoked BCP-X for this
disruption", distinct from the technical failover event.

Lifecycle (deterministic single-host state machine):
1. ``plan()`` registers one continuity plan for a business-function
   scope (``people`` / ``process`` / ``technology`` / ``facilities`` /
   ``supply-chain`` / ``communications``) with a pinned criticality
   (``critical`` / ``high`` / ``medium`` / ``low``). Plan ids are never
   recycled; duplicate registration is refused fail-closed.
2. ``test()`` books one declared BCP exercise against a plan. The
   exercise kind and the host-reported outcome (``pass`` / ``fail`` /
   ``inconclusive``) are booked **as data**, never proof the exercise
   was run or passed. Findings travel as a ``sha256:`` digest pin only.
3. ``activate()`` books the declared invocation of a plan for a
   disruption. It is fail-closed: a plan with no booked *passing*
   exercise refuses activation (an untested plan may not be invoked),
   and a plan that already has an active activation refuses a second
   one. The disruption scenario travels as a digest pin only.
4. ``deactivate()`` closes the active activation (reasons pinned to
   ``manual`` / ``disruption-resolved`` / ``plan-superseded`` /
   ``stand-down``); the plan returns to ``ready`` and may be activated
   again. History is kept; activations are never deleted.

Design (house style): frozen dataclasses, caller int seqs strictly
increasing (claim-then-burn: failed mutations consume their seq + book
``bcp.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed taxonomy, stdlib-only + the
single ``canonical_json`` try/except fallback, ``sha256:`` digest pins
with ``verify()``, ``audit.ndjson/1`` events, version pin ``bcp.v1``,
schema pin ``northstar.bcp.v1``, ``main()`` self-check.

Honest scope: this module books *declared* continuity posture. It runs
no exercise, invokes no real continuity measures, and cannot prove a
plan would work in a real disruption. A booked ``pass`` means "the host
declared a passing exercise", never "the plan is sound". A booked
activation means "the host declared it invoked the plan", never that
anyone followed it.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

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
VERSION = "bcp.v1"

#: Schema pin carried by records and audit events.
SCHEMA = "northstar.bcp.v1"

KIND_PLANNED = "planned"
KIND_TESTED = "tested"
KIND_ACTIVATED = "activated"
KIND_DEACTIVATED = "deactivated"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_PLANNED, KIND_TESTED, KIND_ACTIVATED, KIND_DEACTIVATED,
    KIND_REJECTED,
})

#: Pinned business-function scopes a plan may cover.
_SCOPES = (
    "people", "process", "technology", "facilities", "supply-chain",
    "communications",
)

#: Pinned plan criticality vocabulary.
_CRITICALITIES = ("critical", "high", "medium", "low")

#: Pinned BCP exercise-kind vocabulary (classic exercise taxonomy).
_TEST_KINDS = (
    "walkthrough", "simulation", "parallel", "full-interruption",
    "checklist",
)

#: Pinned exercise-outcome vocabulary (booked as data).
_OUTCOMES = ("pass", "fail", "inconclusive")

#: Pinned deactivation-reason vocabulary.
_REASONS = (
    "manual", "disruption-resolved", "plan-superseded", "stand-down",
)

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "description", "text", "payload", "raw", "content", "rationale",
    "notes", "note", "findings", "scenario", "objective", "plan_text",
    "disruption", "business_unit",
})


# ---------------------------------------------------------------------------
# Fail-closed error taxonomy
# ---------------------------------------------------------------------------


class BCPError(Exception):
    """Base class for all BCP ledger errors."""


class BadIdError(BCPError):
    """Malformed plan id or test id."""


class DuplicatePlanError(BCPError):
    """Plan id already registered (ids are never recycled)."""


class UnknownPlanError(BCPError):
    """No plan is pinned under the requested id."""


class BadScopeError(BCPError):
    """Scope not in the pinned vocabulary."""


class BadCriticalityError(BCPError):
    """Criticality not in the pinned vocabulary."""


class BadDigestError(BCPError):
    """Digest is not a sha256:<64hex> pin (or empty)."""


class BadKindError(BCPError):
    """Exercise kind not in the pinned vocabulary."""


class BadOutcomeError(BCPError):
    """Exercise outcome not in the pinned vocabulary."""


class DuplicateTestError(BCPError):
    """Test id already booked for this plan (ids never recycled)."""


class NoPassingTestError(BCPError):
    """Plan has no booked passing exercise; activation refused."""


class AlreadyActiveError(BCPError):
    """Plan already has an active activation."""


class NotActiveError(BCPError):
    """Plan has no active activation to close."""


class BadReasonError(BCPError):
    """Deactivation reason not in the pinned vocabulary."""


class SeqOrderError(BCPError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(BCPError):
    """Unknown audit kind, or banned key at the audit boundary."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str) -> str:
    """Validate a sha256:<64hex> digest pin (or empty string)."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{label} must be str, got {type(value).__name__}")
    if value and not _DIGEST_RE.match(value):
        raise BadDigestError(f"{label} must be sha256:<64hex> or empty")
    return value


def _digest_pin(payload: Any) -> str:
    """sha256: digest pin over canonical JSON of payload."""
    return "sha256:" + jcs_sha256_hex(payload)


def bcp_audit_event(audit_kind: str, detail: Dict[str, object],
                    seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the BCP ledger."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "audit_version": "audit.ndjson/1",
        "schema": SCHEMA,
        "version": VERSION,
        "kind": "bcp." + audit_kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"bcp": tag, **fields})


@dataclass(frozen=True)
class PlanRecord:
    """One declared business continuity plan."""

    plan_id: str
    scope: str
    criticality: str
    objective_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "plan_id": self.plan_id,
            "scope": self.scope,
            "criticality": self.criticality,
            "objective_pin": self.objective_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("plan", {
            "plan_id": self.plan_id, "scope": self.scope,
            "criticality": self.criticality,
            "objective_pin": self.objective_pin})


@dataclass(frozen=True)
class TestRecord:
    """One declared BCP exercise against a plan.

    ``outcome`` is host-reported bookkeeping data (GIGO), never proof
    the exercise was run or passed; ``findings_pin`` pins the findings
    by digest only - the findings text never enters a record.
    """

    test_id: str
    plan_id: str
    kind: str
    outcome: str
    findings_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "test_id": self.test_id,
            "plan_id": self.plan_id,
            "kind": self.kind,
            "outcome": self.outcome,
            "findings_pin": self.findings_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("test", {
            "test_id": self.test_id, "plan_id": self.plan_id,
            "kind": self.kind, "outcome": self.outcome,
            "findings_pin": self.findings_pin})


@dataclass(frozen=True)
class ActivationRecord:
    """One declared invocation of a plan (minted act-N).

    Books the *decision* that the host invoked the plan for a declared
    disruption; the scenario travels as a digest pin only. ``active``
    is the ledger state at booking time.
    """

    act_id: str
    plan_id: str
    scenario_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "act_id": self.act_id,
            "plan_id": self.plan_id,
            "scenario_pin": self.scenario_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("activation", {
            "act_id": self.act_id, "plan_id": self.plan_id,
            "scenario_pin": self.scenario_pin})


@dataclass(frozen=True)
class DeactivationRecord:
    """One declared closure of a plan activation (minted dct-N)."""

    dct_id: str
    plan_id: str
    act_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "dct_id": self.dct_id,
            "plan_id": self.plan_id,
            "act_id": self.act_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("deactivation", {
            "dct_id": self.dct_id, "plan_id": self.plan_id,
            "act_id": self.act_id, "reason": self.reason})


@dataclass(frozen=True)
class StatusReport:
    """Pure-read snapshot of one plan's continuity posture.

    ``state`` is ``ready`` or ``active``; outcome tallies are derived
    from booked exercises; ``integrity_ok`` re-derives every digest pin.
    """

    plan_id: str
    state: str
    tests: int
    passed: int
    failed: int
    inconclusive: int
    active_act_id: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "plan_id": self.plan_id,
            "state": self.state,
            "tests": self.tests,
            "passed": self.passed,
            "failed": self.failed,
            "inconclusive": self.inconclusive,
            "active_act_id": self.active_act_id,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("status", {
            "plan_id": self.plan_id, "state": self.state,
            "tests": self.tests, "passed": self.passed,
            "failed": self.failed, "inconclusive": self.inconclusive,
            "active_act_id": self.active_act_id,
            "integrity_ok": self.integrity_ok})


class BCP:
    """Business continuity plan governance ledger.

    Simulated: books declared plans, exercises, activations, and
    deactivations. No wall-clock, no randomness, no real exercises, no
    real invocations.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._plans: Dict[str, PlanRecord] = {}
        self._tests: Dict[Tuple[str, str], TestRecord] = {}
        self._activations: Dict[str, ActivationRecord] = {}
        self._deactivations: Dict[str, DeactivationRecord] = {}
        # plan_id -> act_id of the currently active activation (if any).
        self._active: Dict[str, str] = {}
        self._act_counter = 0
        self._dct_counter = 0
        self._audit_log: List[Dict[str, object]] = []
        self._rejected = 0

    def _claim_seq(self, seq: int) -> None:
        """Claim-then-burn: seq must be strictly increasing."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be > {self._seq}, got {seq}")

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        self._audit_log.append(bcp_audit_event(audit_kind, detail, seq))

    def _burn(self, seq: int, what: str, exc: BCPError) -> None:
        self._seq = seq
        self._rejected += 1
        self._emit(KIND_REJECTED,
                   {"what": what, "why": type(exc).__name__}, seq)

    def plan(self, plan_id: object, scope: object, seq: object,
             criticality: object = "medium",
             objective_digest: object = "") -> PlanRecord:
        """Register one continuity plan; fail-closed on misuse."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(plan_id, "plan_id")
                if pid in self._plans:
                    raise DuplicatePlanError(
                        f"plan already registered: {pid!r}")
                if not isinstance(scope, str) or scope not in _SCOPES:
                    raise BadScopeError(
                        f"scope must be one of {sorted(_SCOPES)}")
                if (not isinstance(criticality, str)
                        or criticality not in _CRITICALITIES):
                    raise BadCriticalityError(
                        f"criticality must be one of {sorted(_CRITICALITIES)}")
                pin = _check_digest(objective_digest, "objective_digest")
                rec = PlanRecord(
                    plan_id=pid, scope=scope, criticality=criticality,
                    objective_pin=pin,
                    digest=_record_digest("plan", {
                        "plan_id": pid, "scope": scope,
                        "criticality": criticality,
                        "objective_pin": pin}))
                self._plans[pid] = rec
                self._seq = seq_v
                self._emit(KIND_PLANNED,
                           {"plan_id": pid, "scope": scope,
                            "criticality": criticality}, seq_v)
                return rec
            except BCPError as exc:
                self._burn(seq_v, "plan", exc)
                raise

    def test(self, plan_id: object, test_id: object, seq: object,
             kind: object = "walkthrough", outcome: object = "pass",
             findings_digest: object = "") -> TestRecord:
        """Book one declared BCP exercise against a plan."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(plan_id, "plan_id")
                if pid not in self._plans:
                    raise UnknownPlanError(f"unknown plan: {pid!r}")
                tid = _check_id(test_id, "test_id")
                key = (pid, tid)
                if key in self._tests:
                    raise DuplicateTestError(
                        f"test already booked: {tid!r} for plan {pid!r}")
                if not isinstance(kind, str) or kind not in _TEST_KINDS:
                    raise BadKindError(
                        f"kind must be one of {sorted(_TEST_KINDS)}")
                if not isinstance(outcome, str) or outcome not in _OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(_OUTCOMES)}")
                pin = _check_digest(findings_digest, "findings_digest")
                rec = TestRecord(
                    test_id=tid, plan_id=pid, kind=kind, outcome=outcome,
                    findings_pin=pin,
                    digest=_record_digest("test", {
                        "test_id": tid, "plan_id": pid, "kind": kind,
                        "outcome": outcome, "findings_pin": pin}))
                self._tests[key] = rec
                self._seq = seq_v
                self._emit(KIND_TESTED,
                           {"test_id": tid, "plan_id": pid, "kind": kind,
                            "outcome": outcome}, seq_v)
                return rec
            except BCPError as exc:
                self._burn(seq_v, "test", exc)
                raise

    def activate(self, plan_id: object, seq: object,
                 scenario_digest: object = "") -> ActivationRecord:
        """Declare the invocation of a plan for a disruption.

        Fail-closed: unknown plans refused; plans with no booked
        passing exercise refused; plans already in an active activation
        refused.
        """
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(plan_id, "plan_id")
                if pid not in self._plans:
                    raise UnknownPlanError(f"unknown plan: {pid!r}")
                pin = _check_digest(scenario_digest, "scenario_digest")
                if pid in self._active:
                    raise AlreadyActiveError(
                        f"plan already active: {pid!r}")
                if not any(t.plan_id == pid and t.outcome == "pass"
                           for t in self._tests.values()):
                    raise NoPassingTestError(
                        f"plan has no booked passing exercise: {pid!r}")
                self._act_counter += 1
                act_id = f"act-{self._act_counter}"
                rec = ActivationRecord(
                    act_id=act_id, plan_id=pid, scenario_pin=pin,
                    digest=_record_digest("activation", {
                        "act_id": act_id, "plan_id": pid,
                        "scenario_pin": pin}))
                self._activations[act_id] = rec
                self._active[pid] = act_id
                self._seq = seq_v
                self._emit(KIND_ACTIVATED,
                           {"act_id": act_id, "plan_id": pid}, seq_v)
                return rec
            except BCPError as exc:
                self._burn(seq_v, "activate", exc)
                raise

    def deactivate(self, plan_id: object, seq: object,
                   reason: object = "manual") -> DeactivationRecord:
        """Close the active activation of a plan."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(plan_id, "plan_id")
                if pid not in self._plans:
                    raise UnknownPlanError(f"unknown plan: {pid!r}")
                if not isinstance(reason, str) or reason not in _REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(_REASONS)}")
                act_id = self._active.get(pid)
                if act_id is None:
                    raise NotActiveError(
                        f"plan has no active activation: {pid!r}")
                self._dct_counter += 1
                dct_id = f"dct-{self._dct_counter}"
                rec = DeactivationRecord(
                    dct_id=dct_id, plan_id=pid, act_id=act_id,
                    reason=reason,
                    digest=_record_digest("deactivation", {
                        "dct_id": dct_id, "plan_id": pid, "act_id": act_id,
                        "reason": reason}))
                self._deactivations[dct_id] = rec
                del self._active[pid]
                self._seq = seq_v
                self._emit(KIND_DEACTIVATED,
                           {"dct_id": dct_id, "plan_id": pid,
                            "act_id": act_id, "reason": reason}, seq_v)
                return rec
            except BCPError as exc:
                self._burn(seq_v, "deactivate", exc)
                raise

    # ----- pure-read views (seq validated, never consumed, no audit rows) ---

    def plan_record(self, plan_id: object, seq: object) -> PlanRecord:
        """Pure read: fetch one plan record (no seq consumption)."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(plan_id, "plan_id")
            if pid not in self._plans:
                raise UnknownPlanError(f"unknown plan: {pid!r}")
            return self._plans[pid]

    def plan_ids(self, seq: object) -> Tuple[str, ...]:
        """Pure read: all plan ids in registration order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._plans.keys())

    def tests_for(self, plan_id: object, seq: object) -> Tuple[str, ...]:
        """Pure read: test ids booked for one plan, in booking order."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(plan_id, "plan_id")
            if pid not in self._plans:
                raise UnknownPlanError(f"unknown plan: {pid!r}")
            return tuple(t.test_id for t in self._tests.values()
                         if t.plan_id == pid)

    def test_record(self, plan_id: object, test_id: object,
                    seq: object) -> TestRecord:
        """Pure read: fetch one test record (no seq consumption)."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(plan_id, "plan_id")
            tid = _check_id(test_id, "test_id")
            key = (pid, tid)
            if key not in self._tests:
                raise UnknownPlanError(
                    f"unknown test: {tid!r} for plan {pid!r}")
            return self._tests[key]

    def activations_for(self, plan_id: object,
                        seq: object) -> Tuple[str, ...]:
        """Pure read: activation ids booked for one plan, in order."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(plan_id, "plan_id")
            if pid not in self._plans:
                raise UnknownPlanError(f"unknown plan: {pid!r}")
            return tuple(a.act_id for a in self._activations.values()
                         if a.plan_id == pid)

    def is_active(self, plan_id: object, seq: object) -> bool:
        """Pure read: whether the plan has an active activation."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(plan_id, "plan_id")
            if pid not in self._plans:
                raise UnknownPlanError(f"unknown plan: {pid!r}")
            return pid in self._active

    def status(self, plan_id: object, seq: object) -> StatusReport:
        """Pure read: derived continuity posture of one plan.

        Seq is shape-validated but never consumed; no audit rows are
        written. Digest tamper is reported as data (``integrity_ok``),
        never raised.
        """
        with self._lock:
            _check_seq(seq)
            pid = _check_id(plan_id, "plan_id")
            if pid not in self._plans:
                raise UnknownPlanError(f"unknown plan: {pid!r}")
            plan = self._plans[pid]
            booked = [t for t in self._tests.values() if t.plan_id == pid]
            passed = sum(1 for t in booked if t.outcome == "pass")
            failed = sum(1 for t in booked if t.outcome == "fail")
            inconclusive = sum(
                1 for t in booked if t.outcome == "inconclusive")
            integrity = plan.verify() and all(t.verify() for t in booked)
            active_act_id = self._active.get(pid, "")
            state = "active" if active_act_id else "ready"
            return StatusReport(
                plan_id=pid, state=state, tests=len(booked),
                passed=passed, failed=failed, inconclusive=inconclusive,
                active_act_id=active_act_id, integrity_ok=integrity,
                digest=_record_digest("status", {
                    "plan_id": pid, "state": state,
                    "tests": len(booked), "passed": passed,
                    "failed": failed, "inconclusive": inconclusive,
                    "active_act_id": active_act_id,
                    "integrity_ok": integrity}))

    def stats(self, seq: object) -> Dict[str, int]:
        """Pure read: ledger counts."""
        with self._lock:
            _check_seq(seq)
            return {
                "plans": len(self._plans),
                "tests": len(self._tests),
                "activations": len(self._activations),
                "deactivations": len(self._deactivations),
                "active": len(self._active),
                "rejected": self._rejected,
                "seq": self._seq,
            }

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        """Pure read: the audit rows booked so far."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit_log)


def main() -> None:
    """Self-check smoke: plan, test, activate, deactivate, pins, audit."""
    bcp = BCP()
    plan = bcp.plan("plan-tech", "technology", 1, criticality="high",
                    objective_digest="sha256:" + "a" * 64)
    assert plan.verify()
    tst = bcp.test("plan-tech", "t-1", 2, kind="simulation",
                   outcome="pass", findings_digest="sha256:" + "b" * 64)
    assert tst.verify()
    act = bcp.activate("plan-tech", 3,
                       scenario_digest="sha256:" + "c" * 64)
    assert act.verify()
    rep = bcp.status("plan-tech", 4)
    assert rep.verify()
    assert rep.state == "active" and rep.active_act_id == "act-1"
    assert rep.passed == 1 and rep.integrity_ok
    dct = bcp.deactivate("plan-tech", 5, reason="disruption-resolved")
    assert dct.verify()
    assert bcp.status("plan-tech", 6).state == "ready"
    assert bcp.stats(6)["rejected"] == 0
    assert len(bcp.audit_log(6)) == 4
    print("bcp OK: plan, test, activate, deactivate, pins, audit")


if __name__ == "__main__":
    main()
