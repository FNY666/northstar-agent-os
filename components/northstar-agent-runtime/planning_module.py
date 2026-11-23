"""Task-decomposition planning (goal/decompose/sequence/execute) interface, simulated.

Research motivation: the decompose-then-execute loop (Plan-and-Execute,
ReWOO, ReAct's thought/act cycle) is the skeleton of every agent planner:
declare a goal, split it into steps, order the steps with dependencies,
then execute steps in topological order while predecessors' outcomes
gate successors. The recurring production failure is the planner-executor
seam -- steps booked out of order, cyclic dependency graphs, or silent
re-planning after execution started corrupting the run.

This module is the *planning ledger* half of that shape:

- ``PlanningModule.goal(goal_id, description, seq)`` -- declare a goal.
  Returns a frozen ``GoalRecord`` with a ``sha256:`` digest pin.
  Duplicate ids are refused fail-closed; ids are never recycled.
- ``PlanningModule.decompose(goal_id, plan_id, steps, seq)`` -- book one
  decomposition of a goal into an ordered list of steps, where ``steps``
  is a sequence of ``(step_id, description)`` pairs. Returns a frozen
  ``DecompositionRecord``. Duplicate plan ids are refused fail-closed.
- ``PlanningModule.sequence(plan_id, dependencies, seq)`` -- book a
  dependency DAG over the plan's steps (``(before, after)`` pairs) and
  deterministically derive the topological execution order. Returns a
  frozen ``SequenceRecord`` with a revision counter. Cyclic graphs are
  refused fail-closed; re-sequencing a plan that already has booked
  executions is refused (silent re-planning after execution started is
  the seam this ledger closes).
- ``PlanningModule.execute(plan_id, step_id, outcome, seq)`` -- book the
  host-declared outcome of one step execution. Returns a frozen
  ``ExecutionRecord`` with a minted ``exec-N`` id. Outcomes are the
  pinned vocabulary ``done`` / ``failed`` / ``skipped`` -- a verdict is
  *data*, never raised. Executing a step whose declared predecessors are
  not all ``done`` raises ``OutOfOrderError`` fail-closed. Retrying a
  failed step books another record; the step's status is its latest.
- ``PlanningModule.plan_state(plan_id, seq)`` -- pure read view of every
  step with its status (``pending`` / outcome of latest execution).
- ``PlanningModule.next_steps(plan_id, seq)`` -- pure read view of the
  steps whose predecessors are all ``done`` and which are not yet done,
  in topological order (seq validated, never consumed, no audit row).
- ``planning_module_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``goal-registered`` / ``decomposed`` / ``sequenced`` /
  ``executed`` / ``rejected``); caller-supplied seqs only. Raw
  descriptions never cross the audit boundary -- audit rows carry ids,
  counts, and digest pins only.

Fail-closed edges (fail loudly, never guess):

- ``goal_id`` / ``plan_id`` / ``step_id`` must be non-empty strs,
  <= 256 chars, no whitespace.
- ``decompose`` requires a known goal; ``steps`` must be a non-empty
  sequence of ``(step_id, description)`` pairs with unique step ids and
  non-empty descriptions.
- ``sequence`` requires a known plan; dependencies must name known,
  distinct steps; self-dependencies, duplicate pairs, and cycles are
  refused.
- ``execute`` requires a known plan and step; ``outcome`` must be one
  of ``done`` / ``failed`` / ``skipped``; predecessors must all be
  ``done`` (``OutOfOrderError`` otherwise).
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* plans and *host-reported* step
  outcomes. A booked ``done`` is a ledger entry, not proof the step
  actually ran -- outcomes are GIGO: the module cannot observe the
  executor or verify work happened.
- ``next_steps()`` derives eligibility deterministically from the
  booked ledger; it is readiness bookkeeping, never a scheduling
  guarantee (no deadlines, priorities, or resource model).
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if plan state must survive a restart.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

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
PLANNING_MODULE_VERSION = "planning-module.v1"

#: Schema pin carried by records and audit events.
PLANNING_MODULE_SCHEMA = "northstar.planning-module.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_GOAL_REGISTERED = "goal-registered"
KIND_DECOMPOSED = "decomposed"
KIND_SEQUENCED = "sequenced"
KIND_EXECUTED = "executed"
KIND_REJECTED = "rejected"
_KINDS = (KIND_GOAL_REGISTERED, KIND_DECOMPOSED, KIND_SEQUENCED,
          KIND_EXECUTED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw text never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"description", "descriptions", "text", "payload", "raw", "data"})

#: Pinned outcome vocabulary for step executions.
OUTCOMES = ("done", "failed", "skipped")

#: Max id length.
_MAX_ID_LEN = 256

#: Max description length.
_MAX_DESCRIPTION_LEN = 1024


class PlanningModuleError(Exception):
    """Base error for the planning ledger (programming errors)."""


class BadGoalError(PlanningModuleError):
    """Raised when a goal id or description is malformed."""


class DuplicateGoalError(PlanningModuleError):
    """Raised when a goal id is registered twice."""


class UnknownGoalError(PlanningModuleError):
    """Raised when a goal id names no declared goal."""


class BadPlanError(PlanningModuleError):
    """Raised when a plan id or decomposition is malformed."""


class DuplicatePlanError(PlanningModuleError):
    """Raised when a plan id is decomposed twice."""


class UnknownPlanError(PlanningModuleError):
    """Raised when a plan id names no booked decomposition."""


class BadStepError(PlanningModuleError):
    """Raised when a step id or description is malformed."""


class DuplicateStepError(PlanningModuleError):
    """Raised when a step id repeats inside one decomposition."""


class UnknownStepError(PlanningModuleError):
    """Raised when a step id names no step of the plan."""


class BadDependencyError(PlanningModuleError):
    """Raised when a dependency pair is malformed or redundant."""


class CyclicDependencyError(PlanningModuleError):
    """Raised when dependencies form a cycle."""


class BadOutcomeError(PlanningModuleError):
    """Raised when an execution outcome is outside the pinned vocabulary."""


class OutOfOrderError(PlanningModuleError):
    """Raised when a step executes before its predecessors are done."""


class PlanExecutingError(PlanningModuleError):
    """Raised when re-sequencing a plan that already has executions."""


class SeqOrderError(PlanningModuleError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(PlanningModuleError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, kind: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise PlanningModuleError(
            f"{kind} id must be str, got {type(value).__name__}")
    if not value:
        raise PlanningModuleError(f"{kind} id must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise PlanningModuleError(
            f"{kind} id too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise PlanningModuleError(f"{kind} id must not contain whitespace")
    return value


def _check_goal_id(goal_id: object) -> str:
    """Validate a goal id (error taxonomy: BadGoalError)."""
    try:
        return _check_id(goal_id, "goal")
    except PlanningModuleError as e:
        raise BadGoalError(str(e)) from e


def _check_plan_id(plan_id: object) -> str:
    """Validate a plan id (error taxonomy: BadPlanError)."""
    try:
        return _check_id(plan_id, "plan")
    except PlanningModuleError as e:
        raise BadPlanError(str(e)) from e


def _check_step_id(step_id: object) -> str:
    """Validate a step id (error taxonomy: BadStepError)."""
    try:
        return _check_id(step_id, "step")
    except PlanningModuleError as e:
        raise BadStepError(str(e)) from e


def _check_description(description: object, kind: str) -> str:
    """Validate a description: non-empty str, <= 1024 chars."""
    if isinstance(description, bool) or not isinstance(description, str):
        raise BadGoalError(
            f"{kind} description must be str, got {type(description).__name__}")
    if not description:
        raise BadGoalError(f"{kind} description must not be empty")
    if len(description) > _MAX_DESCRIPTION_LEN:
        raise BadGoalError(
            f"{kind} description too long (>{_MAX_DESCRIPTION_LEN} chars)")
    return description


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": PLANNING_MODULE_SCHEMA,
        "parts": list(parts),
    })


def planning_module_audit_event(kind: str, detail: Dict[str, object],
                                seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the planning ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": PLANNING_MODULE_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def _topo_sort(step_ids: Sequence[str],
               dependencies: Sequence[Tuple[str, str]]) -> Tuple[str, ...]:
    """Deterministic Kahn topological sort (declared order tie-break)."""
    successors: Dict[str, List[str]] = {s: [] for s in step_ids}
    indegree: Dict[str, int] = {s: 0 for s in step_ids}
    seen: set = set()
    for before, after in dependencies:
        if (before, after) in seen:
            raise BadDependencyError(
                f"duplicate dependency: {before!r} -> {after!r}")
        seen.add((before, after))
        successors[before].append(after)
        indegree[after] += 1
    order = list(step_ids)  # declared order = deterministic tie-break
    rank = {s: i for i, s in enumerate(order)}
    ready = sorted([s for s in step_ids if indegree[s] == 0],
                   key=lambda s: rank[s])
    out: List[str] = []
    while ready:
        node = ready.pop(0)
        out.append(node)
        for nxt in successors[node]:
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                ready.append(nxt)
        ready.sort(key=lambda s: rank[s])
    if len(out) != len(step_ids):
        raise CyclicDependencyError(
            "dependencies contain a cycle")
    return tuple(out)


@dataclass(frozen=True)
class GoalRecord:
    """Frozen record of a declared planning goal."""
    goal_id: str
    seq: int
    digest: str

    def verify(self, goal_id: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("goal", goal_id, self.seq)


@dataclass(frozen=True)
class DecompositionRecord:
    """Frozen record of one goal decomposition into ordered steps."""
    plan_id: str
    goal_id: str
    # Step ids in declared order.
    step_ids: Tuple[str, ...]
    # Parallel descriptions (host-provided text, pinned by digest only in
    # audit rows -- audit rows carry ids, counts, and pins, never text).
    descriptions: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self, plan_id: str, goal_id: str,
               step_ids: Tuple[str, ...], seq: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("decompose", plan_id, goal_id,
                                   list(step_ids), seq)


@dataclass(frozen=True)
class SequenceRecord:
    """Frozen record of a dependency DAG + derived execution order."""
    plan_id: str
    # (before, after) dependency pairs as booked.
    dependencies: Tuple[Tuple[str, str], ...]
    # Deterministically derived topological execution order.
    topo_order: Tuple[str, ...]
    # 1-based revision of the plan's sequence history.
    revision: int
    seq: int
    digest: str

    def verify(self, plan_id: str,
               dependencies: Tuple[Tuple[str, str], ...],
               revision: int, seq: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "sequence", plan_id, [[b, a] for b, a in dependencies],
            revision, seq)


@dataclass(frozen=True)
class ExecutionRecord:
    """Frozen record of one host-declared step execution."""
    exec_id: str
    plan_id: str
    step_id: str
    outcome: str
    seq: int
    digest: str

    def verify(self, plan_id: str, step_id: str, outcome: str,
               seq: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("execute", self.exec_id, plan_id,
                                   step_id, outcome, seq)


@dataclass(frozen=True)
class StepStatus:
    """Per-step derived status as data (not a record)."""
    step_id: str
    # "pending" when never executed, else the latest booked outcome.
    status: str
    executions: int


@dataclass(frozen=True)
class PlanStateView:
    """Pure read view of a plan's steps with statuses (not consumed)."""
    plan_id: str
    steps: Tuple[StepStatus, ...]
    topo_order: Tuple[str, ...]
    seq: int


@dataclass(frozen=True)
class NextStepsReport:
    """Pure read view of steps eligible to execute next (not consumed)."""
    plan_id: str
    next_step_ids: Tuple[str, ...]
    seq: int


class PlanningModule:
    """Deterministic task-decomposition planning ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._goals: Dict[str, GoalRecord] = {}
        self._plans: Dict[str, DecompositionRecord] = {}
        self._sequences: Dict[str, List[SequenceRecord]] = {}
        self._executions: Dict[str, List[ExecutionRecord]] = {}
        self._exec_counter = 0
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq: int, error: Exception) -> None:
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(planning_module_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        self._audit.append(
            planning_module_audit_event(audit_kind, detail, seq))

    # -- mutations ---------------------------------------------------------

    def goal(self, goal_id: object, description: object,
             seq: object) -> GoalRecord:
        """Declare a planning goal; duplicate ids refused fail-closed."""
        with self._lock:
            seq = self._claim(seq)
            try:
                goal_id = _check_goal_id(goal_id)
                _check_description(description, "goal")
                if goal_id in self._goals:
                    raise DuplicateGoalError(
                        f"goal already registered: {goal_id!r}")
            except PlanningModuleError as e:
                self._burn(seq, e)
            rec = GoalRecord(goal_id=goal_id, seq=seq,
                             digest=_pin("goal", goal_id, seq))
            self._goals[goal_id] = rec
            self._last_seq = seq
            # Description banned from the audit boundary: digest pin only.
            self._emit(KIND_GOAL_REGISTERED,
                       {"goal_id": goal_id, "digest": rec.digest}, seq)
            return rec

    def decompose(self, goal_id: object, plan_id: object, steps: object,
                  seq: object) -> DecompositionRecord:
        """Book one decomposition of a goal into ordered steps."""
        with self._lock:
            seq = self._claim(seq)
            try:
                goal_id = _check_goal_id(goal_id)
                plan_id = _check_plan_id(plan_id)
                if goal_id not in self._goals:
                    raise UnknownGoalError(f"unknown goal: {goal_id!r}")
                if plan_id in self._plans:
                    raise DuplicatePlanError(
                        f"plan already decomposed: {plan_id!r}")
                step_ids, descriptions = self._check_steps(steps)
            except PlanningModuleError as e:
                self._burn(seq, e)
            rec = DecompositionRecord(
                plan_id=plan_id, goal_id=goal_id, step_ids=step_ids,
                descriptions=descriptions, seq=seq,
                digest=_pin("decompose", plan_id, goal_id,
                            list(step_ids), seq))
            self._plans[plan_id] = rec
            self._last_seq = seq
            # Step descriptions banned from the audit boundary: count + pin.
            self._emit(KIND_DECOMPOSED,
                       {"plan_id": plan_id, "goal_id": goal_id,
                        "step_count": len(step_ids),
                        "digest": rec.digest}, seq)
            return rec

    @staticmethod
    def _check_steps(steps: object) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        """Validate the steps sequence -> (step_ids, descriptions)."""
        if isinstance(steps, (str, bytes)) or not isinstance(
                steps, Sequence):
            raise BadPlanError(
                f"steps must be a sequence of (step_id, description) pairs, "
                f"got {type(steps).__name__}")
        pairs = list(steps)
        if not pairs:
            raise BadPlanError("steps must not be empty")
        step_ids: List[str] = []
        descriptions: List[str] = []
        seen: set = set()
        for pair in pairs:
            if (not isinstance(pair, (tuple, list)) or len(pair) != 2):
                raise BadPlanError(
                    f"each step must be a (step_id, description) pair, "
                    f"got {pair!r}")
            step_id = _check_step_id(pair[0])
            description = _check_description(pair[1], "step")
            if step_id in seen:
                raise DuplicateStepError(
                    f"duplicate step id in plan: {step_id!r}")
            seen.add(step_id)
            step_ids.append(step_id)
            descriptions.append(description)
        return tuple(step_ids), tuple(descriptions)

    def sequence(self, plan_id: object, dependencies: object,
                 seq: object) -> SequenceRecord:
        """Book a dependency DAG and derive the deterministic order."""
        with self._lock:
            seq = self._claim(seq)
            try:
                plan_id = _check_plan_id(plan_id)
                if plan_id not in self._plans:
                    raise UnknownPlanError(f"unknown plan: {plan_id!r}")
                if plan_id in self._executions and self._executions[plan_id]:
                    raise PlanExecutingError(
                        f"plan already has booked executions: {plan_id!r}")
                plan = self._plans[plan_id]
                pairs = self._check_dependencies(plan, dependencies)
                topo = _topo_sort(plan.step_ids, pairs)
                revision = len(self._sequences.get(plan_id, ())) + 1
            except PlanningModuleError as e:
                self._burn(seq, e)
            rec = SequenceRecord(
                plan_id=plan_id, dependencies=pairs, topo_order=topo,
                revision=revision, seq=seq,
                digest=_pin("sequence", plan_id,
                            [[b, a] for b, a in pairs], revision, seq))
            self._sequences.setdefault(plan_id, []).append(rec)
            self._last_seq = seq
            self._emit(KIND_SEQUENCED,
                       {"plan_id": plan_id, "revision": revision,
                        "dependency_count": len(pairs),
                        "digest": rec.digest}, seq)
            return rec

    @staticmethod
    def _check_dependencies(plan: DecompositionRecord,
                            dependencies: object) -> Tuple[Tuple[str, str], ...]:
        """Validate dependency pairs against the plan's steps."""
        if dependencies is None:
            dependencies = ()
        if not isinstance(dependencies, Sequence) or isinstance(
                dependencies, (str, bytes)):
            raise BadDependencyError(
                f"dependencies must be a sequence of (before, after) pairs, "
                f"got {type(dependencies).__name__}")
        step_set = set(plan.step_ids)
        out: List[Tuple[str, str]] = []
        for pair in dependencies:
            if (not isinstance(pair, (tuple, list)) or len(pair) != 2):
                raise BadDependencyError(
                    f"each dependency must be a (before, after) pair, "
                    f"got {pair!r}")
            before = _check_step_id(pair[0])
            after = _check_step_id(pair[1])
            if before not in step_set:
                raise UnknownStepError(
                    f"dependency names unknown step: {before!r}")
            if after not in step_set:
                raise UnknownStepError(
                    f"dependency names unknown step: {after!r}")
            if before == after:
                raise BadDependencyError(
                    f"self-dependency refused: {before!r}")
            out.append((before, after))
        return tuple(out)

    def execute(self, plan_id: object, step_id: object, outcome: object,
                seq: object) -> ExecutionRecord:
        """Book the host-declared outcome of one step execution."""
        with self._lock:
            seq = self._claim(seq)
            try:
                plan_id = _check_plan_id(plan_id)
                step_id = _check_step_id(step_id)
                if plan_id not in self._plans:
                    raise UnknownPlanError(f"unknown plan: {plan_id!r}")
                plan = self._plans[plan_id]
                if step_id not in plan.step_ids:
                    raise UnknownStepError(
                        f"step {step_id!r} not in plan {plan_id!r}")
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {OUTCOMES}, "
                        f"got {outcome!r}")
                self._check_predecessors_done(plan_id, plan, step_id)
            except PlanningModuleError as e:
                self._burn(seq, e)
            self._exec_counter += 1
            exec_id = f"exec-{self._exec_counter}"
            rec = ExecutionRecord(
                exec_id=exec_id, plan_id=plan_id, step_id=step_id,
                outcome=outcome, seq=seq,
                digest=_pin("execute", exec_id, plan_id, step_id,
                            outcome, seq))
            self._executions.setdefault(plan_id, []).append(rec)
            self._last_seq = seq
            self._emit(KIND_EXECUTED,
                       {"exec_id": exec_id, "plan_id": plan_id,
                        "step_id": step_id, "outcome": outcome,
                        "digest": rec.digest}, seq)
            return rec

    def _check_predecessors_done(self, plan_id: str,
                                 plan: DecompositionRecord,
                                 step_id: str) -> None:
        """Fail-closed gate: every declared predecessor must be done."""
        sequence = self._latest_sequence(plan_id)
        predecessors = {before for before, after in
                        sequence.dependencies if after == step_id} \
            if sequence is not None else set()
        for pred in sorted(predecessors):
            if self._latest_outcome(plan_id, pred) != "done":
                raise OutOfOrderError(
                    f"step {step_id!r} blocked: predecessor {pred!r} "
                    f"is not done")

    # -- derived state (internal) ------------------------------------------

    def _latest_sequence(self, plan_id: str) -> Optional[SequenceRecord]:
        """Latest booked SequenceRecord, or None when unsequenced."""
        history = self._sequences.get(plan_id)
        return history[-1] if history else None

    def _latest_outcome(self, plan_id: str, step_id: str) -> Optional[str]:
        """Outcome of the latest booked execution, or None when pending."""
        latest: Optional[str] = None
        for rec in self._executions.get(plan_id, ()):
            if rec.step_id == step_id:
                latest = rec.outcome
        return latest

    def _statuses_locked(self, plan_id: str,
                         plan: DecompositionRecord) -> Tuple[StepStatus, ...]:
        """Per-step statuses; call with the lock held."""
        counts: Dict[str, int] = {s: 0 for s in plan.step_ids}
        latest: Dict[str, str] = {}
        for rec in self._executions.get(plan_id, ()):
            counts[rec.step_id] += 1
            latest[rec.step_id] = rec.outcome
        return tuple(StepStatus(step_id=s,
                               status=latest.get(s, "pending"),
                               executions=counts[s])
                     for s in plan.step_ids)

    # -- views --------------------------------------------------------------

    def goal_record(self, goal_id: str) -> Optional[GoalRecord]:
        """Return the goal record, or None when unknown (pure read)."""
        return self._goals.get(goal_id)

    def goal_ids(self) -> Tuple[str, ...]:
        """Sorted declared goal ids (pure read)."""
        return tuple(sorted(self._goals))

    def plan_record(self, plan_id: str) -> Optional[DecompositionRecord]:
        """Return the decomposition record, or None when unknown."""
        return self._plans.get(plan_id)

    def plan_ids(self) -> Tuple[str, ...]:
        """Sorted booked plan ids (pure read)."""
        return tuple(sorted(self._plans))

    def sequence_history(self, plan_id: str) -> Tuple[SequenceRecord, ...]:
        """Booked sequence revisions, oldest first (pure read)."""
        return tuple(self._sequences.get(plan_id, ()))

    def executions(self, plan_id: str) -> Tuple[ExecutionRecord, ...]:
        """Booked execution records, oldest first (pure read)."""
        return tuple(self._executions.get(plan_id, ()))

    def topo_order(self, plan_id: str) -> Tuple[str, ...]:
        """Latest derived execution order, or declared order when
        unsequenced (pure read)."""
        plan = self._plans.get(plan_id)
        if plan is None:
            raise UnknownPlanError(f"unknown plan: {plan_id!r}")
        sequence = self._latest_sequence(plan_id)
        return sequence.topo_order if sequence is not None else plan.step_ids

    def plan_state(self, plan_id: str, seq: object) -> PlanStateView:
        """Pure read view of steps with statuses (seq validated, not consumed)."""
        _check_seq(seq)
        plan = self._plans.get(plan_id)
        if plan is None:
            raise UnknownPlanError(f"unknown plan: {plan_id!r}")
        with self._lock:
            sequence = self._latest_sequence(plan_id)
            return PlanStateView(
                plan_id=plan_id,
                steps=self._statuses_locked(plan_id, plan),
                topo_order=(sequence.topo_order if sequence is not None
                            else plan.step_ids),
                seq=seq)

    def next_steps(self, plan_id: str, seq: object) -> NextStepsReport:
        """Pure read view of steps eligible to execute next."""
        _check_seq(seq)
        plan = self._plans.get(plan_id)
        if plan is None:
            raise UnknownPlanError(f"unknown plan: {plan_id!r}")
        with self._lock:
            sequence = self._latest_sequence(plan_id)
            order = (sequence.topo_order if sequence is not None
                     else plan.step_ids)
            predecessors: Dict[str, set] = {s: set() for s in plan.step_ids}
            if sequence is not None:
                for before, after in sequence.dependencies:
                    predecessors[after].add(before)
            ready = []
            for step_id in order:
                if self._latest_outcome(plan_id, step_id) == "done":
                    continue
                if all(self._latest_outcome(plan_id, p) == "done"
                       for p in predecessors[step_id]):
                    ready.append(step_id)
            return NextStepsReport(plan_id=plan_id,
                                   next_step_ids=tuple(ready), seq=seq)

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main() -> None:
    """Self-check: goal, decompose, sequence, execute in order."""
    pm = PlanningModule()
    g = pm.goal("launch", "ship the agent runtime", 1)
    assert g.verify("launch") and not g.verify("other")
    plan = pm.decompose("launch", "plan-1", [
        ("fetch", "fetch the deps"),
        ("build", "build the wheel"),
        ("ship", "ship the release"),
    ], 2)
    assert plan.verify("plan-1", "launch",
                       ("fetch", "build", "ship"), 2)
    sq = pm.sequence("plan-1", [("fetch", "build"), ("build", "ship")], 3)
    assert sq.topo_order == ("fetch", "build", "ship")
    assert sq.verify("plan-1", (("fetch", "build"), ("build", "ship")), 1, 3)
    # Out-of-order execution refused fail-closed.
    try:
        pm.execute("plan-1", "build", "done", 4)
        raise AssertionError("out-of-order execute must raise")
    except OutOfOrderError:
        pass
    e1 = pm.execute("plan-1", "fetch", "done", 5)
    assert e1.exec_id == "exec-1"
    assert e1.verify("plan-1", "fetch", "done", 5)
    nxt = pm.next_steps("plan-1", 5)
    assert nxt.next_step_ids == ("build",), nxt
    pm.execute("plan-1", "build", "failed", 6)
    # A failed step is eligible again (retry), ship stays blocked.
    assert pm.next_steps("plan-1", 6).next_step_ids == ("build",)
    # Retry books another record; status is the latest.
    pm.execute("plan-1", "build", "done", 7)
    assert pm.next_steps("plan-1", 7).next_step_ids == ("ship",)
    pm.execute("plan-1", "ship", "skipped", 8)
    state = pm.plan_state("plan-1", 8)
    assert {s.step_id: s.status for s in state.steps} == {
        "fetch": "done", "build": "done", "ship": "skipped"}
    # A skipped step stays eligible (re-run or deliberate abandon).
    assert pm.next_steps("plan-1", 8).next_step_ids == ("ship",)
    # Audit: 1 goal + 1 decompose + 1 sequence + 4 executes + 1 rejected.
    assert len(pm.audit_log()) == 8, len(pm.audit_log())
    print("planning-module OK: goal, decompose, sequence, execute, audit")


if __name__ == "__main__":
    main()
