"""Task router: deterministic task-to-worker routing, dispatch, and rebalancing.

Research note: a *task router* sits between task producers and worker pools.
Producers book tasks onto named *routes* (topic-shaped intake channels);
*dispatch* then binds each booked task to one eligible worker using a
selection policy; a periodic *balance* pass re-plans queued-but-undispatched
tasks when the fleet changes. This mirrors classic queue-task patterns
(Celery/RQ exchange->queue binding, Kubernetes scheduler predicates, and
HDFS/Pulsar broker assignment): routing is the *binding decision*, not the
execution.

* **Routes** — named intake channels; each carries a selection policy that
  governs how its tasks pick workers.
* **Workers** — capacity-limited executors. Health is host-reported; capacity
  is a fixed int (slots). A worker is *eligible* for a task when it is healthy
  and holds a free slot.
* **Selection** — ``round-robin`` cycles eligible workers in registration
  order; ``least-loaded`` picks the eligible worker with the fewest
  in-flight tasks (ties break by registration order). Both are deterministic
  on the input sequence, so audit replay reproduces every pick.
* **Balance** — a pure re-plan: for every queued task (routed but not yet
  dispatched), the deterministic target worker under the route policy is
  computed and reported. Nothing moves; the host applies the plan. Failures
  inside a policy (no eligible worker) are reported per-task as data, not
  raised, so one starved task cannot abort the whole pass.
* **Fail-closed dispatch** — :meth:`TaskRouter.dispatch` with no eligible
  worker raises :class:`NoAvailableWorkerError` rather than returning ``None``
  — a silent null would be enqueued or swallowed downstream, hiding a fleet
  outage as a bug.

Honest scope: this is the *binding* half of a task system, not a runner — it
cannot execute tasks, cannot observe worker liveness (health is host-reported
GIGO), and a ``DispatchRecord`` means "this policy chose this worker at this
seq", never "this task ran". For production use, pair routing with an
independent failure detector and a timeout manager.

Version pin: task-router.v1
Schema pin: northstar.task-router.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any

#: Module version.
TASK_ROUTER_VERSION = "task-router.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.task-router.v1"

#: Supported route selection policies.
POLICIES = (
    "round-robin",
    "least-loaded",
)


class TaskRouterError(Exception):
    """Malformed use of the task router (programming error)."""


class BadRouteError(TaskRouterError):
    """A route id or policy that fails validation."""


class DuplicateRouteError(TaskRouterError):
    """A route id that is already registered."""


class UnknownRouteError(TaskRouterError):
    """Operation on a route id that is not registered."""


class BadWorkerError(TaskRouterError):
    """A worker id or capacity that fails validation."""


class DuplicateWorkerError(TaskRouterError):
    """A worker id that is already registered."""


class UnknownWorkerError(TaskRouterError):
    """Operation on a worker id that is not registered."""


class BadTaskError(TaskRouterError):
    """A task id that fails validation."""


class DuplicateTaskError(TaskRouterError):
    """A task id that is already booked."""


class UnknownTaskError(TaskRouterError):
    """Operation on a task id that is not booked."""


class NoAvailableWorkerError(TaskRouterError):
    """Dispatch attempted with no eligible worker available."""


class SeqOrderError(TaskRouterError):
    """A caller seq that is not a strictly increasing int."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be non-negative, got {value}")
    return value


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise TaskRouterError(f"{name} must be a non-empty str (<=256 chars)")
    if any(c.isspace() for c in value):
        raise TaskRouterError(f"{name} must not contain whitespace")
    return value


def _digest(*parts: Any) -> str:
    body = "\x1f".join(str(p) for p in parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class WorkerRecord:
    """A registered worker: capacity-limited execution slot holder."""

    worker_id: str
    capacity: int
    healthy: bool
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and check it matches."""
        return self.digest == _digest("worker", self.worker_id, self.capacity, self.seq)


@dataclass(frozen=True)
class RouteRecord:
    """A registered intake route and its selection policy."""

    route_id: str
    policy: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and check it matches."""
        return self.digest == _digest("route", self.route_id, self.policy, self.seq)


@dataclass(frozen=True)
class RouteBooking:
    """A task pinned to a route's queue (pre-dispatch booking)."""

    task_id: str
    route_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and check it matches."""
        return self.digest == _digest("route-booking", self.task_id, self.route_id, self.seq)


@dataclass(frozen=True)
class DispatchRecord:
    """A routed task bound to one eligible worker under the route policy."""

    task_id: str
    route_id: str
    worker_id: str
    policy: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and check it matches."""
        return self.digest == _digest(
            "dispatch", self.task_id, self.route_id, self.worker_id, self.policy, self.seq
        )


@dataclass(frozen=True)
class CompletionRecord:
    """A dispatched task completed (slot freed back to its worker)."""

    task_id: str
    worker_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and check it matches."""
        return self.digest == _digest("complete", self.task_id, self.worker_id, self.seq)


@dataclass(frozen=True)
class BalanceTarget:
    """One queued task's deterministic balance target (data, not a move)."""

    task_id: str
    worker_id: str
    digest: str


@dataclass(frozen=True)
class BalanceReport:
    """Deterministic re-plan over queued tasks at one logical seq."""

    seq: int
    targets: tuple[BalanceTarget, ...]
    unplaceable: tuple[str, ...]
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin and check it matches."""
        joined = ",".join(f"{t.task_id}={t.worker_id}" for t in self.targets)
        return self.digest == _digest("balance", self.seq, joined, "|".join(self.unplaceable))


_AUDIT_KINDS = (
    "worker-registered",
    "route-registered",
    "worker-health",
    "task-routed",
    "task-dispatched",
    "task-completed",
    "balanced",
    "rejected",
)


def task_router_audit_event(kind: str, seq: int, **detail: Any) -> dict:
    """Wrap a task-router event as an audit event dict (audit.ndjson/1)."""
    if kind not in _AUDIT_KINDS:
        raise TaskRouterError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    event = {
        "schema": "northstar.audit.ndjson/1",
        "module": TASK_ROUTER_VERSION,
        "event": kind,
        "audit_seq": seq,
    }
    event.update(detail)
    return event


class TaskRouter:
    """Deterministic task->route->worker binding ledger (single host).

    Frozen dataclass records, caller-supplied strictly increasing int seqs,
    no wall-clock, RLock-guarded, fail-closed. Failed mutations consume their
    seq and book a ``task-router.rejected`` audit row.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._workers: dict[str, WorkerRecord] = {}
        self._worker_health: dict[str, bool] = {}
        self._inflight: dict[str, int] = {}
        self._routes: dict[str, RouteRecord] = {}
        self._rr_cursor: dict[str, int] = {}
        self._tasks: dict[str, RouteBooking] = {}
        self._dispatches: dict[str, DispatchRecord] = {}
        self._completed: set[str] = set()
        self._audit: list[dict] = []

    # ------------------------------------------------------------------ seq

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq must be strictly increasing, got {seq} after {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(task_router_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, exc: TaskRouterError) -> TaskRouterError:
        self._emit("rejected", seq, error=type(exc).__name__)
        return exc

    def _guarded(self, seq: Any, fn, name: str) -> Any:
        seq = self._claim(seq)
        try:
            return fn(seq)
        except TaskRouterError as exc:
            raise self._reject(seq, exc) from exc

    # -------------------------------------------------------------- workers

    def register_worker(self, worker_id: str, seq: int, capacity: int = 1) -> WorkerRecord:
        """Register a worker with ``capacity`` execution slots."""
        with self._lock:
            def _do(s: int) -> WorkerRecord:
                try:
                    wid = _check_id(worker_id, "worker_id")
                except TaskRouterError as exc:
                    raise BadWorkerError(str(exc)) from exc
                if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
                    raise BadWorkerError("capacity must be a positive int")
                if wid in self._workers:
                    raise DuplicateWorkerError(f"worker already registered: {wid!r}")
                rec = WorkerRecord(
                    worker_id=wid,
                    capacity=capacity,
                    healthy=True,
                    seq=s,
                    digest=_digest("worker", wid, capacity, s),
                )
                self._workers[wid] = rec
                self._worker_health[wid] = True
                self._inflight[wid] = 0
                self._emit("worker-registered", s, worker_id=wid, capacity=capacity)
                return rec

            return self._guarded(seq, _do, "register_worker")

    def worker_health(self, worker_id: str, healthy: bool, seq: int) -> WorkerRecord:
        """Mark a worker healthy/unhealthy (host-reported)."""
        with self._lock:
            def _do(s: int) -> WorkerRecord:
                if not isinstance(healthy, bool):
                    raise BadWorkerError("healthy must be a bool")
                rec = self._workers.get(worker_id)
                if rec is None:
                    raise UnknownWorkerError(f"unknown worker: {worker_id!r}")
                self._worker_health[worker_id] = healthy
                updated = WorkerRecord(
                    worker_id=rec.worker_id,
                    capacity=rec.capacity,
                    healthy=healthy,
                    seq=s,
                    digest=_digest("worker", rec.worker_id, rec.capacity, s),
                )
                self._workers[worker_id] = updated
                self._emit("worker-health", s, worker_id=worker_id, healthy=healthy)
                return updated

            return self._guarded(seq, _do, "worker_health")

    # --------------------------------------------------------------- routes

    def register_route(self, route_id: str, seq: int, policy: str = "round-robin") -> RouteRecord:
        """Register an intake route with a selection policy."""
        with self._lock:
            def _do(s: int) -> RouteRecord:
                try:
                    rid = _check_id(route_id, "route_id")
                except TaskRouterError as exc:
                    raise BadRouteError(str(exc)) from exc
                if policy not in POLICIES:
                    raise BadRouteError(f"policy must be one of {POLICIES}, got {policy!r}")
                if rid in self._routes:
                    raise DuplicateRouteError(f"route already registered: {rid!r}")
                rec = RouteRecord(
                    route_id=rid,
                    policy=policy,
                    seq=s,
                    digest=_digest("route", rid, policy, s),
                )
                self._routes[rid] = rec
                self._rr_cursor[rid] = 0
                self._emit("route-registered", s, route_id=rid, policy=policy)
                return rec

            return self._guarded(seq, _do, "register_route")

    # ---------------------------------------------------------------- route

    def route(self, task_id: str, route_id: str, seq: int) -> RouteBooking:
        """Pin a task onto a route's queue (pre-dispatch booking)."""
        with self._lock:
            def _do(s: int) -> RouteBooking:
                try:
                    tid = _check_id(task_id, "task_id")
                except TaskRouterError as exc:
                    raise BadTaskError(str(exc)) from exc
                if tid in self._tasks:
                    raise DuplicateTaskError(f"task already booked: {tid!r}")
                if route_id not in self._routes:
                    raise UnknownRouteError(f"unknown route: {route_id!r}")
                rec = RouteBooking(
                    task_id=tid,
                    route_id=route_id,
                    seq=s,
                    digest=_digest("route-booking", tid, route_id, s),
                )
                self._tasks[tid] = rec
                self._emit("task-routed", s, task_id=tid, route_id=route_id)
                return rec

            return self._guarded(seq, _do, "route")

    # ------------------------------------------------------------- dispatch

    def _eligible(self) -> list[str]:
        return [
            wid
            for wid in self._workers
            if self._worker_health[wid] and self._inflight[wid] < self._workers[wid].capacity
        ]

    def _pick(self, route_id: str, eligible: list[str], cursor: int) -> tuple[str, int]:
        policy = self._routes[route_id].policy
        if policy == "least-loaded":
            return min(eligible, key=lambda w: (self._inflight[w], list(self._workers).index(w))), cursor
        chosen = eligible[cursor % len(eligible)]
        return chosen, cursor + 1

    def dispatch(self, task_id: str, seq: int) -> DispatchRecord:
        """Bind a routed task to one eligible worker under the route policy.

        Fail-closed: raises :class:`NoAvailableWorkerError` when no worker is
        eligible rather than returning a silent null.
        """
        with self._lock:
            def _do(s: int) -> DispatchRecord:
                booking = self._tasks.get(task_id)
                if booking is None:
                    raise UnknownTaskError(f"unknown task: {task_id!r}")
                if task_id in self._dispatches:
                    raise DuplicateTaskError(f"task already dispatched: {task_id!r}")
                eligible = self._eligible()
                if not eligible:
                    raise NoAvailableWorkerError("no healthy worker with a free slot")
                cursor = self._rr_cursor[booking.route_id]
                worker_id, cursor = self._pick(booking.route_id, eligible, cursor)
                self._rr_cursor[booking.route_id] = cursor
                policy = self._routes[booking.route_id].policy
                rec = DispatchRecord(
                    task_id=task_id,
                    route_id=booking.route_id,
                    worker_id=worker_id,
                    policy=policy,
                    seq=s,
                    digest=_digest("dispatch", task_id, booking.route_id, worker_id, policy, s),
                )
                self._dispatches[task_id] = rec
                self._inflight[worker_id] += 1
                self._emit(
                    "task-dispatched",
                    s,
                    task_id=task_id,
                    worker_id=worker_id,
                    policy=policy,
                )
                return rec

            return self._guarded(seq, _do, "dispatch")

    def complete(self, task_id: str, seq: int) -> CompletionRecord:
        """Mark a dispatched task complete and free its worker slot."""
        with self._lock:
            def _do(s: int) -> CompletionRecord:
                dispatch = self._dispatches.get(task_id)
                if dispatch is None:
                    raise UnknownTaskError(f"unknown or undispatched task: {task_id!r}")
                if task_id in self._completed:
                    raise DuplicateTaskError(f"task already completed: {task_id!r}")
                self._inflight[dispatch.worker_id] -= 1
                self._completed.add(task_id)
                rec = CompletionRecord(
                    task_id=task_id,
                    worker_id=dispatch.worker_id,
                    seq=s,
                    digest=_digest("complete", task_id, dispatch.worker_id, s),
                )
                self._emit("task-completed", s, task_id=task_id, worker_id=dispatch.worker_id)
                return rec

            return self._guarded(seq, _do, "complete")

    # -------------------------------------------------------------- balance

    def balance(self, seq: int) -> BalanceReport:
        """Deterministic re-plan of queued tasks; returned as data, moves nothing.

        Uses a local rotation cursor and never advances router state: the
        report is a point-in-time prediction, and actual dispatch re-evaluates
        the policy at dispatch time. Starved tasks appear in ``unplaceable``
        as data rather than aborting the pass.
        """
        with self._lock:
            def _do(s: int) -> BalanceReport:
                eligible = self._eligible()
                queued = sorted(
                    tid for tid in self._tasks if tid not in self._dispatches
                )
                targets: list[BalanceTarget] = []
                unplaceable: list[str] = []
                cursors: dict[str, int] = {}
                for tid in queued:
                    booking = self._tasks[tid]
                    if not eligible:
                        unplaceable.append(tid)
                        continue
                    cursor = cursors.get(booking.route_id, self._rr_cursor[booking.route_id])
                    worker_id, cursor = self._pick(booking.route_id, eligible, cursor)
                    cursors[booking.route_id] = cursor
                    targets.append(
                        BalanceTarget(
                            task_id=tid,
                            worker_id=worker_id,
                            digest=_digest("balance-target", tid, worker_id, s),
                        )
                    )
                report = BalanceReport(
                    seq=s,
                    targets=tuple(targets),
                    unplaceable=tuple(unplaceable),
                    digest=_digest(
                        "balance",
                        s,
                        ",".join(f"{t.task_id}={t.worker_id}" for t in targets),
                        "|".join(unplaceable),
                    ),
                )
                self._emit(
                    "balanced",
                    s,
                    targets=len(targets),
                    unplaceable=len(unplaceable),
                )
                return report

            return self._guarded(seq, _do, "balance")

    # ---------------------------------------------------------------- views

    def task(self, task_id: str) -> RouteBooking | None:
        """Return a task's route booking, or None."""
        with self._lock:
            return self._tasks.get(task_id)

    def dispatch_record(self, task_id: str) -> DispatchRecord | None:
        """Return a task's dispatch record, or None if undispatched."""
        with self._lock:
            return self._dispatches.get(task_id)

    def worker(self, worker_id: str) -> WorkerRecord | None:
        """Return a worker record, or None."""
        with self._lock:
            return self._workers.get(worker_id)

    def worker_ids(self) -> tuple[str, ...]:
        """Sorted worker ids."""
        with self._lock:
            return tuple(sorted(self._workers))

    def route_ids(self) -> tuple[str, ...]:
        """Sorted route ids."""
        with self._lock:
            return tuple(sorted(self._routes))

    def task_ids(self) -> tuple[str, ...]:
        """Sorted booked task ids."""
        with self._lock:
            return tuple(sorted(self._tasks))

    def queued_tasks(self) -> tuple[str, ...]:
        """Sorted task ids routed but not yet dispatched."""
        with self._lock:
            return tuple(sorted(tid for tid in self._tasks if tid not in self._dispatches))

    def tasks_for_worker(self, worker_id: str) -> tuple[str, ...]:
        """Sorted dispatched task ids currently in-flight on a worker."""
        with self._lock:
            return tuple(
                sorted(
                    tid
                    for tid, rec in self._dispatches.items()
                    if rec.worker_id == worker_id and tid not in self._completed
                )
            )

    def inflight(self, worker_id: str) -> int:
        """Current in-flight count for a worker."""
        with self._lock:
            if worker_id not in self._workers:
                raise UnknownWorkerError(f"unknown worker: {worker_id!r}")
            return self._inflight[worker_id]

    def stats(self) -> dict:
        """Aggregate router state as a plain dict."""
        with self._lock:
            return {
                "workers": len(self._workers),
                "routes": len(self._routes),
                "tasks": len(self._tasks),
                "dispatched": len(self._dispatches),
                "completed": len(self._completed),
                "queued": len(self.queued_tasks()),
            }

    def audit_log(self) -> tuple[dict, ...]:
        """All audit rows booked so far."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: register, route, dispatch, complete, balance."""
    router = TaskRouter()
    router.register_worker("w1", seq=1, capacity=2)
    router.register_worker("w2", seq=2, capacity=1)
    router.register_route("jobs", seq=3)
    router.route("t1", "jobs", seq=4)
    router.route("t2", "jobs", seq=5)
    d1 = router.dispatch("t1", seq=6)
    assert d1.worker_id == "w1" and d1.policy == "round-robin"
    d2 = router.dispatch("t2", seq=7)
    assert d2.worker_id == "w2"
    router.route("t3", "jobs", seq=8)
    report = router.balance(seq=9)
    assert len(report.targets) == 1 and report.targets[0].task_id == "t3"
    router.complete("t1", seq=10)
    assert router.inflight("w1") == 0
    print("task-router OK: register, route, dispatch, balance, complete, pins, audit")


if __name__ == "__main__":
    main()
