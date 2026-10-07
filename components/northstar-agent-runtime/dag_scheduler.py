"""DAG scheduler: Airflow-shaped task-graph bookkeeping as a deterministic
state machine.

Research motivation: schedulers decide *what runs after what* -- a DAG
scheduler that mis-orders tasks, silently drops a dependency, or lets a
cycle through can turn a recoverable step into a data-loss step. This
module is the *bookkeeping* half of a DAG scheduler: it records the
task graph, computes a deterministic topological order, and books run
and retry decisions. It never executes a task body, never spawns
threads, and never measures real time -- the host applies the booked
order and reports task outcomes; this ledger only proves what was
declared.

Public API:

- ``DAGScheduler`` -- RLock-guarded registry.
  ``add(task_id, seq, depends_on=())`` registers a task node with its
  upstream dependencies (must already be registered; self-dependency
  refused). ``run(run_id, seq, failures=())`` books one DAG run:
  tasks are attempted in deterministic topological order (Kahn's
  algorithm, sorted-id tie-break); host-declared ``failures`` mark
  which tasks failed, everything else is booked ``"success"``.
  ``retry(run_id, task_id, seq)`` books a retry of a task that failed
  in that run -- refused fail-closed unless the task's last status in
  the run is ``"failed"``. ``remove(task_id, seq)`` removes a task that
  nothing depends on (leaf only); the id is retired and never recycled.
- ``topological_order()`` -- pure read view of the task order (seq
  shape validated, never consumed, no audit row).
- ``dag_scheduler_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``
  records, fixed kind vocabulary: ``"task-added"``,
  ``"task-removed"``, ``"run"``, ``"retried"``, ``"rejected"``.

Honest scope:

- The module answers "in what order should these tasks run, and what
  did the host declare about each attempt" -- it does not execute
  anything, does not verify a task actually ran, and cannot detect a
  host that lies about ``failures``. A host that lies about failures
  gets a perfectly consistent ledger of lies (same GIGO boundary as
  every other bookkeeping module in this tree).
- A run's order is fully determined by (task ids, dependency sets):
  identical graphs produce identical orders across instances
  (test-verified). There are no timestamps and no wall-clock anywhere
  in this module.

Version pin: ``dag-scheduler.v1`` / schema pin
``northstar.dag-scheduler.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Set, Tuple

VERSION = "dag-scheduler.v1"
SCHEMA = "northstar.dag-scheduler.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore

    def _canonical(obj: Any) -> bytes:
        return _cj.jcs_dumps(obj).encode("utf-8")

except Exception:  # pragma: no cover

    def _canonical(obj: Any) -> bytes:
        import json

        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


_DIGEST_PREFIX = "sha256:"


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(_canonical([VERSION, *parts])).hexdigest()
    return f"{_DIGEST_PREFIX}{digest}"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DAGError(Exception):
    """Base class for DAG scheduler errors."""


class BadTaskError(DAGError):
    """A task id or dependency list is malformed."""


class DuplicateTaskError(DAGError):
    """A task id is already registered or was retired."""


class UnknownTaskError(DAGError):
    """No registered task with that id."""


class UnknownDependencyError(DAGError):
    """A declared dependency is not registered."""


class SelfDependencyError(DAGError):
    """A task lists itself as a dependency."""


class CycleError(DAGError):
    """The declared edges would close a dependency cycle."""


class TaskInUseError(DAGError):
    """A task cannot be removed while other tasks depend on it."""


class DuplicateRunError(DAGError):
    """A run id is already booked."""


class UnknownRunError(DAGError):
    """No booked run with that id."""


class TaskNotFailedError(DAGError):
    """A retry was booked for a task that did not fail in the run."""


class SeqOrderError(DAGError):
    """A seq did not strictly increase."""


class AuditKindError(DAGError):
    """An audit kind or detail is malformed."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_task_id(task_id: object, what: str = "task id") -> str:
    if not isinstance(task_id, str) or not task_id or len(task_id) > 256:
        raise BadTaskError(f"{what} must be a non-empty str (<=256 chars)")
    if any(c.isspace() for c in task_id):
        raise BadTaskError(f"{what} must not contain whitespace")
    return task_id


def _check_run_id(run_id: object) -> str:
    if not isinstance(run_id, str) or not run_id or len(run_id) > 256:
        raise BadTaskError("run id must be a non-empty str (<=256 chars)")
    if any(c.isspace() for c in run_id):
        raise BadTaskError("run id must not contain whitespace")
    return run_id


def _check_dep(dep: object) -> str:
    return _check_task_id(dep, "dependency")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

KIND_ADDED = "task-added"
KIND_REMOVED = "task-removed"
KIND_RUN = "run"
KIND_RETRIED = "retried"
KIND_REJECTED = "dag-scheduler.rejected"

_KINDS = frozenset({KIND_ADDED, KIND_REMOVED, KIND_RUN, KIND_RETRIED, KIND_REJECTED})


def dag_scheduler_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the DAG scheduler.

    ``detail`` carries ids, counts and digest pins only -- never task
    payloads or host-supplied outcome detail.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"payload", "value", "raw", "body", "data"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaskRecord:
    """One registered DAG node.

    ``depends_on`` is the sorted tuple of upstream task ids. The record
    pins its own content with ``digest``; ``verify()`` recomputes it.
    """

    task_id: str
    depends_on: Tuple[str, ...]
    seq: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "digest", _pin("task", self.task_id, list(self.depends_on), self.seq)
        )

    def verify(self) -> bool:
        return self.digest == _pin(
            "task", self.task_id, list(self.depends_on), self.seq
        )


@dataclass(frozen=True)
class TaskAttempt:
    """One booked attempt of a task inside a run.

    ``status`` is host-declared ``"success"`` / ``"failed"`` -- a
    booking, not proof the host executed anything. ``attempt`` numbers
    attempts of the same task within one run, starting at 1.
    """

    task_id: str
    status: str
    attempt: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "digest", _pin("attempt", self.task_id, self.status, self.attempt)
        )

    def verify(self) -> bool:
        return self.digest == _pin(
            "attempt", self.task_id, self.status, self.attempt
        )


@dataclass(frozen=True)
class RunRecord:
    """One booked DAG run.

    ``order`` is the deterministic topological order of task ids.
    ``attempts`` holds one frozen ``TaskAttempt`` per task, in that
    order.
    """

    run_id: str
    order: Tuple[str, ...]
    attempts: Tuple[TaskAttempt, ...]
    seq: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _pin(
                "run",
                self.run_id,
                list(self.order),
                [a.digest for a in self.attempts],
                self.seq,
            ),
        )

    def verify(self) -> bool:
        return self.digest == _pin(
            "run",
            self.run_id,
            list(self.order),
            [a.digest for a in self.attempts],
            self.seq,
        )


@dataclass(frozen=True)
class RetryRecord:
    """One booked retry of a failed task inside a run.

    The retry books a new ``"success"`` attempt for the task -- the
    host declared the recovery; the ledger pins the declaration.
    """

    run_id: str
    task_id: str
    attempt: int
    seq: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _pin("retry", self.run_id, self.task_id, self.attempt, self.seq),
        )

    def verify(self) -> bool:
        return self.digest == _pin(
            "retry", self.run_id, self.task_id, self.attempt, self.seq
        )


# ---------------------------------------------------------------------------
# The scheduler
# ---------------------------------------------------------------------------


class DAGScheduler:
    """Airflow-shaped DAG scheduling as deterministic bookkeeping.

    Register tasks with ``add()``, book a run with ``run()`` (tasks are
    attempted in topological order; host-declared failures booked as
    data), and book recoveries with ``retry()``. RLock-guarded; caller
    int seqs must strictly increase; failed mutations consume their
    seq and book a ``dag-scheduler.rejected`` audit row.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._tasks: Dict[str, TaskRecord] = {}
        self._retired: Set[str] = set()
        self._runs: Dict[str, RunRecord] = {}
        self._retries: List[RetryRecord] = []
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not exceed last seq {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, task_id: str = "") -> Dict[str, Any]:
        row = dag_scheduler_audit_event(
            KIND_REJECTED, {"reason": reason, "task_id": task_id}, seq
        )
        self._audit.append(row)
        return row

    def _guarded(self, seq: int, task_id: str, fn):  # type: ignore[no-untyped-def]
        """Claim the seq, run fn, and on DAGError burn + audit."""
        self._claim(seq)
        try:
            return fn()
        except DAGError as exc:
            if isinstance(exc, SeqOrderError):
                raise
            self._reject(seq, type(exc).__name__, task_id)
            raise

    # -- graph helpers -----------------------------------------------------

    def _topological_order_locked(self) -> Tuple[str, ...]:
        """Kahn's algorithm with sorted-id tie-break (deterministic)."""
        dependents: Dict[str, Set[str]] = {t: set() for t in self._tasks}
        indegree: Dict[str, int] = {}
        for tid, rec in self._tasks.items():
            indegree[tid] = len(rec.depends_on)
            for dep in rec.depends_on:
                dependents[dep].add(tid)
        ready = sorted(t for t, d in indegree.items() if d == 0)
        order: List[str] = []
        while ready:
            node = ready.pop(0)
            order.append(node)
            for child in sorted(dependents[node]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    ready.append(child)
            ready.sort()
        if len(order) != len(self._tasks):
            raise CycleError("dependency cycle detected")
        return tuple(order)

    # -- mutations ----------------------------------------------------------

    def add(
        self, task_id: str, seq: int, depends_on: Tuple[str, ...] = ()
    ) -> TaskRecord:
        """Register a task node with its upstream dependencies.

        Dependencies must already be registered (fail-closed); the id
        must be fresh (never registered, never retired). Cycle
        introduction is checked defensively before booking.
        """
        with self._lock:

            def _do() -> TaskRecord:
                tid = _check_task_id(task_id)
                if tid in self._tasks or tid in self._retired:
                    raise DuplicateTaskError(f"task {tid!r} already registered")
                if not isinstance(depends_on, tuple):
                    raise BadTaskError("depends_on must be a tuple of task ids")
                deps = tuple(_check_dep(d) for d in depends_on)
                if tid in deps:
                    raise SelfDependencyError(f"task {tid!r} depends on itself")
                for dep in deps:
                    if dep not in self._tasks:
                        raise UnknownDependencyError(
                            f"dependency {dep!r} is not registered"
                        )
                rec = TaskRecord(
                    task_id=tid, depends_on=tuple(sorted(set(deps))), seq=seq
                )
                # Defensive: the graph must stay acyclic even if a
                # future API allows dependency edits.
                self._tasks[tid] = rec
                try:
                    self._topological_order_locked()
                except CycleError:
                    del self._tasks[tid]
                    raise
                self._audit.append(
                    dag_scheduler_audit_event(
                        KIND_ADDED,
                        {
                            "task_id": tid,
                            "depends_on": list(rec.depends_on),
                            "digest": rec.digest,
                        },
                        seq,
                    )
                )
                return rec

            return self._guarded(seq, task_id if isinstance(task_id, str) else "", _do)

    def remove(self, task_id: str, seq: int) -> None:
        """Remove a leaf task (nothing depends on it).

        The id is retired and can never be re-registered.
        """
        with self._lock:

            def _do() -> None:
                tid = _check_task_id(task_id)
                if tid not in self._tasks:
                    raise UnknownTaskError(f"unknown task {tid!r}")
                for other, rec in self._tasks.items():
                    if tid in rec.depends_on:
                        raise TaskInUseError(
                            f"task {tid!r} is depended on by {other!r}"
                        )
                del self._tasks[tid]
                self._retired.add(tid)
                self._audit.append(
                    dag_scheduler_audit_event(KIND_REMOVED, {"task_id": tid}, seq)
                )

            self._guarded(seq, task_id if isinstance(task_id, str) else "", _do)

    def run(
        self, run_id: str, seq: int, failures: Tuple[str, ...] = ()
    ) -> RunRecord:
        """Book one DAG run over the registered tasks.

        Tasks are attempted in deterministic topological order.
        ``failures`` is the host-declared set of tasks that failed --
        booking, not proof; everything else is booked ``"success"``.
        """
        with self._lock:

            def _do() -> RunRecord:
                rid = _check_run_id(run_id)
                if rid in self._runs:
                    raise DuplicateRunError(f"run {rid!r} already booked")
                if not isinstance(failures, tuple):
                    raise BadTaskError("failures must be a tuple of task ids")
                failed = set()
                for f in failures:
                    ftid = _check_task_id(f, "failure id")
                    if ftid not in self._tasks:
                        raise UnknownTaskError(f"failure id {ftid!r} unknown")
                    failed.add(ftid)
                order = self._topological_order_locked()
                attempts = tuple(
                    TaskAttempt(
                        task_id=tid,
                        status="failed" if tid in failed else "success",
                        attempt=1,
                    )
                    for tid in order
                )
                rec = RunRecord(run_id=rid, order=order, attempts=attempts, seq=seq)
                self._runs[rid] = rec
                self._audit.append(
                    dag_scheduler_audit_event(
                        KIND_RUN,
                        {
                            "run_id": rid,
                            "order": list(order),
                            "failed": sorted(failed),
                            "digest": rec.digest,
                        },
                        seq,
                    )
                )
                return rec

            return self._guarded(seq, run_id if isinstance(run_id, str) else "", _do)

    def retry(self, run_id: str, task_id: str, seq: int) -> RetryRecord:
        """Book a retry of a task that failed in a run.

        Refused fail-closed unless the task's last booked attempt in
        the run has status ``"failed"``.
        """
        with self._lock:

            def _do() -> RetryRecord:
                rid = _check_run_id(run_id)
                tid = _check_task_id(task_id)
                run = self._runs.get(rid)
                if run is None:
                    raise UnknownRunError(f"unknown run {rid!r}")
                statuses = [
                    a for a in run.attempts if a.task_id == tid
                ]
                if not statuses:
                    raise UnknownTaskError(f"task {tid!r} not in run {rid!r}")
                # Retries book new attempts; find the latest attempt no.
                latest = max(a.attempt for a in statuses)
                extra = [r for r in self._retries if r.run_id == rid and r.task_id == tid]
                if extra:
                    latest = max(latest, max(r.attempt for r in extra))
                    last_status = "success"  # every booked retry is success
                else:
                    last_status = statuses[-1].status
                if last_status != "failed":
                    raise TaskNotFailedError(
                        f"task {tid!r} did not fail in run {rid!r}"
                    )
                rec = RetryRecord(run_id=rid, task_id=tid, attempt=latest + 1, seq=seq)
                self._retries.append(rec)
                self._audit.append(
                    dag_scheduler_audit_event(
                        KIND_RETRIED,
                        {
                            "run_id": rid,
                            "task_id": tid,
                            "attempt": rec.attempt,
                            "digest": rec.digest,
                        },
                        seq,
                    )
                )
                return rec

            return self._guarded(seq, task_id if isinstance(task_id, str) else "", _do)

    # -- pure views ---------------------------------------------------------

    def topological_order(self, seq: int) -> Tuple[str, ...]:
        """Deterministic task order. Pure read: validates seq, consumes nothing."""
        _check_seq(seq)
        with self._lock:
            return self._topological_order_locked()

    def task_record(self, task_id: str) -> Optional[TaskRecord]:
        with self._lock:
            return self._tasks.get(task_id)

    def task_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._tasks))

    def run_record(self, run_id: str) -> Optional[RunRecord]:
        with self._lock:
            return self._runs.get(run_id)

    def run_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._runs))

    def retries_for(self, run_id: str) -> Tuple[RetryRecord, ...]:
        with self._lock:
            return tuple(r for r in self._retries if r.run_id == run_id)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read view of ledger counters. Validates seq, consumes nothing."""
        _check_seq(seq)
        with self._lock:
            return {
                "tasks": len(self._tasks),
                "retired": len(self._retired),
                "runs": len(self._runs),
                "retries": len(self._retries),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    s = DAGScheduler()
    assert VERSION == "dag-scheduler.v1"
    assert SCHEMA == "northstar.dag-scheduler.v1"

    a = s.add("a", 1)
    b = s.add("b", 2, depends_on=("a",))
    c = s.add("c", 3, depends_on=("a",))
    d = s.add("d", 4, depends_on=("b", "c"))
    assert all(r.verify() for r in (a, b, c, d))
    assert s.topological_order(0) == ("a", "b", "c", "d")
    # Cross-instance determinism: same graph, same order.
    s2 = DAGScheduler()
    for i, tid in enumerate(("a", "b", "c", "d")):
        deps = {"b": ("a",), "c": ("a",), "d": ("b", "c")}.get(tid, ())
        s2.add(tid, i + 1, depends_on=deps)
    assert s2.topological_order(0) == ("a", "b", "c", "d")

    run = s.run("run-1", 5, failures=("c",))
    assert run.verify()
    statuses = {at.task_id: at.status for at in run.attempts}
    assert statuses == {"a": "success", "b": "success", "c": "failed", "d": "success"}

    r = s.retry("run-1", "c", 6)
    assert r.verify() and r.attempt == 2
    try:
        s.retry("run-1", "c", 7)
    except TaskNotFailedError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected TaskNotFailedError")

    # Fail-closed: unknown dependency, self-dependency, duplicate.
    for bad, exc in (
        (lambda: s.add("e", 8, depends_on=("nope",)), UnknownDependencyError),
        (lambda: s.add("e", 9, depends_on=("e",)), SelfDependencyError),
        (lambda: s.add("a", 10), DuplicateTaskError),
    ):
        try:
            bad()
        except exc:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected {exc.__name__}")
    assert s.audit_log()[-1]["kind"] == KIND_REJECTED

    kinds = [row["kind"] for row in s.audit_log()]
    assert kinds[:5] == [KIND_ADDED] * 4 + [KIND_RUN], kinds

    print("dag-scheduler OK: add, order, run, retry, fail-closed, audit")


if __name__ == "__main__":
    main()
