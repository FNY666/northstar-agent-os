"""Workflow orchestration (Airflow/Temporal-shaped control plane).

Airflow DAG / Temporal workflow-style orchestration bookkeeping as a
deterministic single-host ledger:

* :meth:`WorkflowOrchestration.dag` registers a DAG as *data*: task ids,
  per-task retry policies, and upstream/downstream dependency pairs.
  Dependencies are cycle-checked (Kahn's algorithm) and the topological
  order is booked into the immutable :class:`DAGRecord` (``dag-N`` ids).
* :meth:`WorkflowOrchestration.execute` starts a run (``run-N`` ids),
  booking one ``pending`` :class:`TaskInstanceRecord` per DAG task in
  topological order.
* :meth:`WorkflowOrchestration.complete_task` books a host-reported task
  outcome as data (``succeeded`` / ``failed``). Readiness is enforced:
  a task may only complete once all its upstreams have succeeded.
* :meth:`WorkflowOrchestration.retry` re-opens a failed task for another
  attempt, booking a :class:`RetryRecord` (``retry-N`` ids) with the
  per-task ``max_retries`` budget enforced and a logical-seq backoff
  window recorded (advisory — no timers anywhere).
* :meth:`WorkflowOrchestration.cancel_run` terminates a run; the run
  status is otherwise derived from its task instances
  (``succeeded`` / ``failed`` / ``running``).

This is the control plane, not the executor: the module books *decisions
and host-reported outcomes* but never runs task code. ``workflow_engine``
executes injected callables; this module records that a DAG exists, that
a run started, and that the host reported task outcomes in a valid
order.

House rules: no wall-clock (callers inject integer seqs), frozen
dataclasses, fail-closed validation (structural problems raise), RLock
guard for concurrent callers, stdlib-only, records sealed with
``sha256:`` digest pins over type-tagged canonical payloads (bool is not
int; floats refused; ``|int| >= 2**53`` refused — batch-5 JCS discipline).
Every mutation requires a strictly increasing seq; failed mutations
consume their seq too, so the audit trail stays totally ordered.
State transitions emit ``audit.ndjson/1`` events carrying ids, digests,
and counts only — dependency graphs and task payloads never cross the
audit boundary.

Honest boundary: an ``succeeded`` task instance means the host *reported*
success — the module cannot run the task, observe the wire, or prove the
report is true. Pair with a real scheduler/executor for production.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from threading import RLock
from typing import Any, Dict, List, Mapping, Sequence, Tuple

#: Version pin for this module's record shape.
WORKFLOW_ORCHESTRATION_VERSION = "workflow-orchestration.v1"

#: Schema pin carried by records and audit events.
WORKFLOW_ORCHESTRATION_SCHEMA = "northstar.workflow-orchestration.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Genesis marker for the first record in a hash chain.
_GENESIS = "genesis"

#: Audit event kinds.
KIND_DAG_REGISTERED = "workflow.dag-registered"
KIND_RUN_STARTED = "workflow.run-started"
KIND_TASK_COMPLETED = "workflow.task-completed"
KIND_TASK_RETRIED = "workflow.task-retried"
KIND_RUN_CANCELLED = "workflow.run-cancelled"
KIND_REJECTED = "workflow.rejected"
_KINDS = (
    KIND_DAG_REGISTERED,
    KIND_RUN_STARTED,
    KIND_TASK_COMPLETED,
    KIND_TASK_RETRIED,
    KIND_RUN_CANCELLED,
    KIND_REJECTED,
)

#: Validation caps.
MAX_ID_LEN = 128
MAX_TASKS = 512
MAX_DEPS = 4096
MAX_REASON_LEN = 512
MAX_DIGEST_LEN = 80

#: Safe integer range for pins (JCS >2^53 discipline).
_SAFE_INT = 2 ** 53

#: Task instance states.
STATE_PENDING = "pending"
STATE_SUCCEEDED = "succeeded"
STATE_FAILED = "failed"
_TASK_STATES = (STATE_PENDING, STATE_SUCCEEDED, STATE_FAILED)

#: Derived run states.
RUN_RUNNING = "running"
RUN_SUCCEEDED = "succeeded"
RUN_FAILED = "failed"
RUN_CANCELLED = "cancelled"


class WorkflowOrchestrationError(ValueError):
    """A malformed request or a refused state transition."""


class SeqOrderError(WorkflowOrchestrationError):
    """A mutation seq that is not strictly greater than the last one."""


class BadDAGError(WorkflowOrchestrationError):
    """A DAG definition that is structurally malformed."""


class DuplicateDAGError(WorkflowOrchestrationError):
    """A DAG id that is already registered."""


class UnknownDAGError(WorkflowOrchestrationError):
    """Reference to a DAG id the ledger does not hold."""


class UnknownRunError(WorkflowOrchestrationError):
    """Reference to a run id the ledger does not hold."""


class UnknownTaskError(WorkflowOrchestrationError):
    """Reference to a task id the run's DAG does not define."""


class TaskNotReadyError(WorkflowOrchestrationError):
    """A task completed before its upstreams succeeded."""


class BadCompletionError(WorkflowOrchestrationError):
    """A task outcome outside the booked lifecycle."""


class BadRetryError(WorkflowOrchestrationError):
    """A retry request that violates the task retry policy."""


class MaxAttemptsError(WorkflowOrchestrationError):
    """A retry request after the task's retry budget is exhausted."""


class TerminalRunError(WorkflowOrchestrationError):
    """A mutation against a cancelled (terminal) run."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{field_name} must be a non-negative int")
    return value


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadDAGError(f"{name} must be a non-empty string")
    if len(value) > MAX_ID_LEN:
        raise BadDAGError(f"{name} exceeds {MAX_ID_LEN} chars")
    for ch in value:
        if not (ch.isalnum() or ch in "-_."):
            raise BadDAGError(f"{name} has illegal char {ch!r}")
    return value


def _check_nonneg_int(value: Any, name: str, cap: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadDAGError(f"{name} must be an int")
    if value < 0 or value > cap:
        raise BadDAGError(f"{name} out of range [0, {cap}]")
    return value


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise BadCompletionError(f"{name} must be a string")
    if value and (
        len(value) > MAX_DIGEST_LEN
        or not value.startswith("sha256:")
        or len(value) != 7 + 64
    ):
        raise BadCompletionError(f"{name} must be '' or 'sha256:' + 64 hex")
    if value:
        try:
            int(value[7:], 16)
        except ValueError:
            raise BadCompletionError(f"{name} must be '' or 'sha256:' + 64 hex")
    return value


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _tag(value: Any) -> Any:
    # Type-tagged so bool != int and None != 0 in pins.
    if isinstance(value, bool):
        return ["bool", value]
    if value is None:
        return ["none", 0]
    if isinstance(value, int):
        if abs(value) >= _SAFE_INT:
            raise WorkflowOrchestrationError(
                f"int |{value}| exceeds 2**53 pin range"
            )
        return ["int", value]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, dict):
        return ["dict", [[k, _tag(v)] for k, v in
                         sorted(value.items(), key=lambda kv: kv[0])]]
    if isinstance(value, (list, tuple)):
        return ["list", [_tag(v) for v in value]]
    raise WorkflowOrchestrationError(f"cannot encode {type(value).__name__}")


def _canonical(obj: Any) -> bytes:
    return json.dumps(_tag(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _pin(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DAGRecord:
    """One registered DAG: tasks, dependencies, topological order (frozen)."""

    record_id: str
    dag_id: str
    tasks: Tuple[Tuple[str, int, int], ...]
    dependencies: Tuple[Tuple[str, str], ...]
    topo_order: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = WORKFLOW_ORCHESTRATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(_dag_payload(self))

    def task_ids(self) -> Tuple[str, ...]:
        return tuple(t[0] for t in self.tasks)

    def retry_policy(self, task_id: str) -> Tuple[int, int]:
        for tid, max_retries, backoff in self.tasks:
            if tid == task_id:
                return max_retries, backoff
        raise UnknownTaskError(f"unknown task {task_id!r}")


def _dag_payload(rec: DAGRecord) -> Dict[str, Any]:
    return {
        "record_id": rec.record_id,
        "dag_id": rec.dag_id,
        "tasks": [list(t) for t in rec.tasks],
        "dependencies": [list(d) for d in rec.dependencies],
        "topo_order": list(rec.topo_order),
        "seq": rec.seq,
    }


@dataclass(frozen=True)
class TaskInstanceRecord:
    """One task's state inside a run (frozen; replaced on transitions)."""

    run_id: str
    task_id: str
    state: str
    attempts: int
    last_result_digest: str
    seq: int
    digest: str
    schema: str = WORKFLOW_ORCHESTRATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(_task_payload(self))


def _task_payload(rec: TaskInstanceRecord) -> Dict[str, Any]:
    return {
        "run_id": rec.run_id,
        "task_id": rec.task_id,
        "state": rec.state,
        "attempts": rec.attempts,
        "last_result_digest": rec.last_result_digest,
        "seq": rec.seq,
    }


@dataclass(frozen=True)
class RunRecord:
    """One started run (frozen). Status is derived via ``run_status``."""

    run_id: str
    dag_id: str
    cancelled: bool
    cancel_reason: str
    cancel_seq: int
    seq: int
    digest: str
    schema: str = WORKFLOW_ORCHESTRATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(_run_payload(self))


def _run_payload(rec: RunRecord) -> Dict[str, Any]:
    return {
        "run_id": rec.run_id,
        "dag_id": rec.dag_id,
        "cancelled": rec.cancelled,
        "cancel_reason": rec.cancel_reason,
        "cancel_seq": rec.cancel_seq,
        "seq": rec.seq,
    }


@dataclass(frozen=True)
class RetryRecord:
    """One booked retry for a failed task (frozen)."""

    retry_id: str
    run_id: str
    task_id: str
    attempt: int
    backoff_until_seq: int
    seq: int
    digest: str
    schema: str = WORKFLOW_ORCHESTRATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(_retry_payload(self))


def _retry_payload(rec: RetryRecord) -> Dict[str, Any]:
    return {
        "retry_id": rec.retry_id,
        "run_id": rec.run_id,
        "task_id": rec.task_id,
        "attempt": rec.attempt,
        "backoff_until_seq": rec.backoff_until_seq,
        "seq": rec.seq,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

# Keys that may never cross the audit boundary (raw task specs, full
# dependency lists, task payloads / result bytes). Digest pins are fine.
_BANNED_AUDIT_KEYS = {
    "tasks", "dependencies", "spec", "payload", "result",
}


def workflow_orchestration_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for workflow orchestration.

    Carries ids, digests, and counts only — dependency graphs, task
    specs, and result bytes never cross the audit boundary.
    """
    if kind not in _KINDS:
        raise WorkflowOrchestrationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if any(k in detail for k in _BANNED_AUDIT_KEYS):
        raise WorkflowOrchestrationError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "workflow_orchestration",
        "module_version": WORKFLOW_ORCHESTRATION_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# DAG topology
# ---------------------------------------------------------------------------


def _topological_order(
    task_ids: Sequence[str], deps: Sequence[Tuple[str, str]]
) -> Tuple[str, ...]:
    """Kahn's algorithm, deterministic via sorted ties. Raises on cycles."""
    children: Dict[str, List[str]] = {t: [] for t in task_ids}
    indegree: Dict[str, int] = {t: 0 for t in task_ids}
    for up, down in deps:
        children[up].append(down)
        indegree[down] += 1
    ready = sorted(t for t in task_ids if indegree[t] == 0)
    order: List[str] = []
    while ready:
        node = ready.pop(0)
        order.append(node)
        for child in sorted(children[node]):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
        ready.sort()
    if len(order) != len(task_ids):
        raise BadDAGError("dependency graph contains a cycle")
    return tuple(order)


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class WorkflowOrchestration:
    """Deterministic DAG-registration / run / retry ledger.

    All mutations require a strictly increasing caller-supplied ``seq``
    (logical time — no wall-clock reads anywhere). Failed mutations
    consume their seq (batch-21 discipline), keeping the audit trail
    totally ordered. RLock-guarded for concurrent callers.

    The module books decisions and host-reported outcomes; it never
    executes task code (see :mod:`workflow_engine` for execution).
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._dags: Dict[str, DAGRecord] = {}
        self._runs: Dict[str, RunRecord] = {}
        self._instances: Dict[Tuple[str, str], TaskInstanceRecord] = {}
        self._retries: Dict[str, RetryRecord] = {}
        self._audit: List[Mapping[str, Any]] = []
        self._last_seq = -1
        self._next_dag = 0
        self._next_run = 0
        self._next_retry = 0

    # -- internal ------------------------------------------------------

    def _mutation_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str) -> None:
        self._audit.append(
            workflow_orchestration_audit_event(
                KIND_REJECTED, seq, reason=reason
            )
        )

    def _run(self, run_id: str) -> RunRecord:
        try:
            return self._runs[run_id]
        except KeyError:
            raise UnknownRunError(f"unknown run {run_id!r}")

    def _instance(self, run_id: str, task_id: str) -> TaskInstanceRecord:
        try:
            return self._instances[(run_id, task_id)]
        except KeyError:
            raise UnknownTaskError(
                f"unknown task {task_id!r} in run {run_id!r}"
            )

    def _upstreams(self, dag: DAGRecord, task_id: str) -> List[str]:
        return [up for up, down in dag.dependencies if down == task_id]

    # -- DAG -----------------------------------------------------------

    def dag(
        self,
        dag_id: str,
        seq: int,
        tasks: Mapping[str, Mapping[str, Any]],
        dependencies: Sequence[Sequence[str]] = (),
    ) -> DAGRecord:
        """Register a DAG: task retry policies plus dependency pairs.

        ``tasks`` maps task id → ``{"max_retries": int, "backoff_seq": int}``
        (both may be omitted, defaulting to 0). ``dependencies`` is a list
        of ``[upstream, downstream]`` pairs. The graph must be acyclic.
        """
        with self._lock:
            seq = self._mutation_seq(seq)
            try:
                dag_id = _check_id(dag_id, "dag_id")
                if dag_id in self._dags:
                    raise DuplicateDAGError(f"duplicate dag {dag_id!r}")
                if not isinstance(tasks, Mapping) or not tasks:
                    raise BadDAGError("tasks must be a non-empty mapping")
                if len(tasks) > MAX_TASKS:
                    raise BadDAGError(f"too many tasks (>{MAX_TASKS})")
                parsed_tasks: List[Tuple[str, int, int]] = []
                for tid, spec in tasks.items():
                    _check_id(tid, "task id")
                    if not isinstance(spec, Mapping):
                        raise BadDAGError(
                            f"task {tid!r} spec must be a mapping"
                        )
                    max_retries = _check_nonneg_int(
                        spec.get("max_retries", 0), "max_retries", 100
                    )
                    backoff_seq = _check_nonneg_int(
                        spec.get("backoff_seq", 0), "backoff_seq",
                        _SAFE_INT - 1,
                    )
                    for key in spec:
                        if key not in ("max_retries", "backoff_seq"):
                            raise BadDAGError(
                                f"task {tid!r} unknown spec key {key!r}"
                            )
                    parsed_tasks.append((tid, max_retries, backoff_seq))
                seen = [t[0] for t in parsed_tasks]
                if len(set(seen)) != len(seen):
                    raise BadDAGError("duplicate task ids")
                if not isinstance(dependencies, (list, tuple)):
                    raise BadDAGError("dependencies must be a list")
                if len(dependencies) > MAX_DEPS:
                    raise BadDAGError(f"too many dependencies (>{MAX_DEPS})")
                parsed_deps: List[Tuple[str, str]] = []
                for pair in dependencies:
                    if (
                        not isinstance(pair, (list, tuple))
                        or len(pair) != 2
                    ):
                        raise BadDAGError(
                            "each dependency must be [upstream, downstream]"
                        )
                    up, down = pair
                    _check_id(up, "dependency upstream")
                    _check_id(down, "dependency downstream")
                    if up == down:
                        raise BadDAGError("self-loop dependency refused")
                    if up not in seen:
                        raise BadDAGError(
                            f"dependency upstream {up!r} not a task"
                        )
                    if down not in seen:
                        raise BadDAGError(
                            f"dependency downstream {down!r} not a task"
                        )
                    parsed_deps.append((up, down))
                if len(set(parsed_deps)) != len(parsed_deps):
                    raise BadDAGError("duplicate dependency pairs")
                topo = _topological_order(seen, parsed_deps)
                self._next_dag += 1
                rec = DAGRecord(
                    record_id=f"dag-{self._next_dag}",
                    dag_id=dag_id,
                    tasks=tuple(parsed_tasks),
                    dependencies=tuple(parsed_deps),
                    topo_order=topo,
                    seq=seq,
                    digest="",
                    schema=WORKFLOW_ORCHESTRATION_SCHEMA,
                )
                rec = DAGRecord(
                    **{**rec.__dict__, "digest": _pin(_dag_payload(rec))}
                )
                self._dags[dag_id] = rec
                self._audit.append(
                    workflow_orchestration_audit_event(
                        KIND_DAG_REGISTERED, seq,
                        dag_id=dag_id, record_id=rec.record_id,
                        task_count=len(parsed_tasks),
                        dependency_count=len(parsed_deps),
                    )
                )
                return rec
            except WorkflowOrchestrationError as exc:
                self._reject(seq, str(exc))
                raise

    # -- runs ----------------------------------------------------------

    def execute(self, dag_id: str, seq: int) -> RunRecord:
        """Start a run of a registered DAG; all tasks begin ``pending``."""
        with self._lock:
            seq = self._mutation_seq(seq)
            try:
                if dag_id not in self._dags:
                    raise UnknownDAGError(f"unknown dag {dag_id!r}")
                dag = self._dags[dag_id]
                self._next_run += 1
                run_id = f"run-{self._next_run}"
                rec = RunRecord(
                    run_id=run_id, dag_id=dag_id, cancelled=False,
                    cancel_reason="", cancel_seq=0, seq=seq, digest="",
                    schema=WORKFLOW_ORCHESTRATION_SCHEMA,
                )
                rec = RunRecord(
                    **{**rec.__dict__, "digest": _pin(_run_payload(rec))}
                )
                self._runs[run_id] = rec
                for tid in dag.topo_order:
                    inst = TaskInstanceRecord(
                        run_id=run_id, task_id=tid, state=STATE_PENDING,
                        attempts=0, last_result_digest="", seq=seq,
                        digest="", schema=WORKFLOW_ORCHESTRATION_SCHEMA,
                    )
                    inst = TaskInstanceRecord(
                        **{**inst.__dict__,
                           "digest": _pin(_task_payload(inst))}
                    )
                    self._instances[(run_id, tid)] = inst
                self._audit.append(
                    workflow_orchestration_audit_event(
                        KIND_RUN_STARTED, seq, run_id=run_id,
                        dag_id=dag_id, task_count=len(dag.tasks),
                    )
                )
                return rec
            except WorkflowOrchestrationError as exc:
                self._reject(seq, str(exc))
                raise

    def complete_task(
        self,
        run_id: str,
        task_id: str,
        seq: int,
        ok: Any,
        result_digest: str = "",
    ) -> TaskInstanceRecord:
        """Book a host-reported task outcome as data.

        ``ok`` must be a real bool (``True`` → succeeded,
        ``False`` → failed). The task must be ``pending`` and every
        upstream task must already have ``succeeded``.
        """
        with self._lock:
            seq = self._mutation_seq(seq)
            try:
                run = self._run(run_id)
                if run.cancelled:
                    raise TerminalRunError(
                        f"run {run_id!r} is cancelled (terminal)"
                    )
                dag = self._dags[run.dag_id]
                inst = self._instance(run_id, task_id)
                if inst.state != STATE_PENDING:
                    raise BadCompletionError(
                        f"task {task_id!r} is {inst.state}, not pending"
                    )
                if not isinstance(ok, bool):
                    raise BadCompletionError("ok must be a bool")
                result_digest = _check_digest(result_digest, "result_digest")
                for up in self._upstreams(dag, task_id):
                    if self._instances[(run_id, up)].state != STATE_SUCCEEDED:
                        raise TaskNotReadyError(
                            f"upstream {up!r} has not succeeded"
                        )
                state = STATE_SUCCEEDED if ok else STATE_FAILED
                updated = TaskInstanceRecord(
                    run_id=run_id, task_id=task_id, state=state,
                    attempts=inst.attempts + 1,
                    last_result_digest=result_digest, seq=seq, digest="",
                    schema=WORKFLOW_ORCHESTRATION_SCHEMA,
                )
                updated = TaskInstanceRecord(
                    **{**updated.__dict__,
                       "digest": _pin(_task_payload(updated))}
                )
                self._instances[(run_id, task_id)] = updated
                self._audit.append(
                    workflow_orchestration_audit_event(
                        KIND_TASK_COMPLETED, seq, run_id=run_id,
                        task_id=task_id, state=state,
                        attempt=updated.attempts,
                        result_digest=result_digest,
                    )
                )
                return updated
            except WorkflowOrchestrationError as exc:
                self._reject(seq, str(exc))
                raise

    def retry(self, run_id: str, task_id: str, seq: int) -> RetryRecord:
        """Re-open a failed task for another attempt.

        The task's ``max_retries`` budget (from the DAG spec) counts
        retries after the first attempt; exceeding it raises
        :class:`MaxAttemptsError`. Books an advisory logical-seq backoff
        window — no timers are started anywhere.
        """
        with self._lock:
            seq = self._mutation_seq(seq)
            try:
                run = self._run(run_id)
                if run.cancelled:
                    raise TerminalRunError(
                        f"run {run_id!r} is cancelled (terminal)"
                    )
                dag = self._dags[run.dag_id]
                inst = self._instance(run_id, task_id)
                if inst.state != STATE_FAILED:
                    raise BadRetryError(
                        f"task {task_id!r} is {inst.state}, not failed"
                    )
                max_retries, backoff = dag.retry_policy(task_id)
                retries_used = inst.attempts - 1
                if retries_used >= max_retries:
                    raise MaxAttemptsError(
                        f"task {task_id!r} exhausted max_retries={max_retries}"
                    )
                self._next_retry += 1
                retry_id = f"retry-{self._next_retry}"
                backoff_until = seq + backoff
                if backoff_until >= _SAFE_INT:
                    raise BadRetryError("backoff window exceeds pin range")
                rec = RetryRecord(
                    retry_id=retry_id, run_id=run_id, task_id=task_id,
                    attempt=inst.attempts + 1,
                    backoff_until_seq=backoff_until, seq=seq, digest="",
                    schema=WORKFLOW_ORCHESTRATION_SCHEMA,
                )
                rec = RetryRecord(
                    **{**rec.__dict__, "digest": _pin(_retry_payload(rec))}
                )
                self._retries[retry_id] = rec
                reopened = TaskInstanceRecord(
                    run_id=run_id, task_id=task_id, state=STATE_PENDING,
                    attempts=inst.attempts,
                    last_result_digest=inst.last_result_digest, seq=seq,
                    digest="", schema=WORKFLOW_ORCHESTRATION_SCHEMA,
                )
                reopened = TaskInstanceRecord(
                    **{**reopened.__dict__,
                       "digest": _pin(_task_payload(reopened))}
                )
                self._instances[(run_id, task_id)] = reopened
                self._audit.append(
                    workflow_orchestration_audit_event(
                        KIND_TASK_RETRIED, seq, run_id=run_id,
                        task_id=task_id, retry_id=retry_id,
                        attempt=rec.attempt,
                        backoff_until_seq=backoff_until,
                    )
                )
                return rec
            except WorkflowOrchestrationError as exc:
                self._reject(seq, str(exc))
                raise

    def cancel_run(
        self, run_id: str, seq: int, reason: str = ""
    ) -> RunRecord:
        """Terminally cancel a run; further mutations are refused."""
        with self._lock:
            seq = self._mutation_seq(seq)
            try:
                run = self._run(run_id)
                if run.cancelled:
                    raise TerminalRunError(
                        f"run {run_id!r} already cancelled"
                    )
                if not isinstance(reason, str):
                    raise BadDAGError("reason must be a string")
                if len(reason) > MAX_REASON_LEN:
                    raise BadDAGError("reason too long")
                cancelled = RunRecord(
                    run_id=run.run_id, dag_id=run.dag_id, cancelled=True,
                    cancel_reason=reason, cancel_seq=seq, seq=seq,
                    digest="", schema=WORKFLOW_ORCHESTRATION_SCHEMA,
                )
                cancelled = RunRecord(
                    **{**cancelled.__dict__,
                       "digest": _pin(_run_payload(cancelled))}
                )
                self._runs[run_id] = cancelled
                self._audit.append(
                    workflow_orchestration_audit_event(
                        KIND_RUN_CANCELLED, seq, run_id=run_id,
                        reason=reason,
                    )
                )
                return cancelled
            except WorkflowOrchestrationError as exc:
                self._reject(seq, str(exc))
                raise

    # -- views ---------------------------------------------------------

    def run_status(self, run_id: str) -> str:
        """Derived run status: cancelled / succeeded / failed / running."""
        with self._lock:
            run = self._run(run_id)
            if run.cancelled:
                return RUN_CANCELLED
            states = [
                self._instances[(run_id, tid)].state
                for tid in self._dags[run.dag_id].topo_order
            ]
            if all(s == STATE_SUCCEEDED for s in states):
                return RUN_SUCCEEDED
            if any(s == STATE_FAILED for s in states):
                return RUN_FAILED
            return RUN_RUNNING

    def dag_record(self, dag_id: str) -> DAGRecord:
        with self._lock:
            try:
                return self._dags[dag_id]
            except KeyError:
                raise UnknownDAGError(f"unknown dag {dag_id!r}")

    def run_record(self, run_id: str) -> RunRecord:
        with self._lock:
            return self._run(run_id)

    def task_instances(self, run_id: str) -> Tuple[TaskInstanceRecord, ...]:
        with self._lock:
            run = self._run(run_id)
            dag = self._dags[run.dag_id]
            return tuple(
                self._instances[(run_id, tid)] for tid in dag.topo_order
            )

    def retries_for(
        self, run_id: str, task_id: str
    ) -> Tuple[RetryRecord, ...]:
        with self._lock:
            self._run(run_id)
            return tuple(
                r for r in self._retries.values()
                if r.run_id == run_id and r.task_id == task_id
            )

    def dag_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._dags))

    def run_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._runs))

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    def stats(self) -> Mapping[str, int]:
        with self._lock:
            return {
                "dags": len(self._dags),
                "runs": len(self._runs),
                "task_instances": len(self._instances),
                "retries": len(self._retries),
                "audit_events": len(self._audit),
            }


def main() -> None:
    orch = WorkflowOrchestration()
    dag = orch.dag(
        "etl-nightly", 1,
        {
            "extract": {"max_retries": 2, "backoff_seq": 10},
            "transform": {"max_retries": 1},
            "load": {},
        },
        [["extract", "transform"], ["transform", "load"]],
    )
    assert dag.topo_order == ("extract", "transform", "load"), dag.topo_order
    assert dag.verify()
    run = orch.execute("etl-nightly", 2)
    assert orch.run_status(run.run_id) == RUN_RUNNING
    orch.complete_task(run.run_id, "extract", 3, True,
                       result_digest="sha256:" + "ab" * 32)
    orch.complete_task(run.run_id, "transform", 4, False)
    assert orch.run_status(run.run_id) == RUN_FAILED
    ret = orch.retry(run.run_id, "transform", 5)
    assert ret.attempt == 2 and ret.backoff_until_seq == 5, ret
    orch.complete_task(run.run_id, "transform", 6, True)
    orch.complete_task(run.run_id, "load", 7, True)
    assert orch.run_status(run.run_id) == RUN_SUCCEEDED
    kinds = [e["kind"] for e in orch.audit_log()]
    assert kinds == [
        KIND_DAG_REGISTERED, KIND_RUN_STARTED, KIND_TASK_COMPLETED,
        KIND_TASK_COMPLETED, KIND_TASK_RETRIED, KIND_TASK_COMPLETED,
        KIND_TASK_COMPLETED,
    ], kinds
    print("workflow-orchestration OK: dag, execute, complete, retry, "
          "cancel, pins, audit")


if __name__ == "__main__":
    main()


__all__ = [
    "WORKFLOW_ORCHESTRATION_VERSION",
    "WORKFLOW_ORCHESTRATION_SCHEMA",
    "AUDIT_SCHEMA",
    "KIND_DAG_REGISTERED",
    "KIND_RUN_STARTED",
    "KIND_TASK_COMPLETED",
    "KIND_TASK_RETRIED",
    "KIND_RUN_CANCELLED",
    "KIND_REJECTED",
    "WorkflowOrchestrationError",
    "SeqOrderError",
    "BadDAGError",
    "DuplicateDAGError",
    "UnknownDAGError",
    "UnknownRunError",
    "UnknownTaskError",
    "TaskNotReadyError",
    "BadCompletionError",
    "BadRetryError",
    "MaxAttemptsError",
    "TerminalRunError",
    "DAGRecord",
    "TaskInstanceRecord",
    "RunRecord",
    "RetryRecord",
    "WorkflowOrchestration",
    "workflow_orchestration_audit_event",
    "main",
]
