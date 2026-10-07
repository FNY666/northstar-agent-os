"""Task queue: Celery-style durable task dispatch bookkeeping.

Research note: Celery (the dominant Python distributed task queue) splits
work into *producers* (enqueue named tasks with args/kwargs), *brokers*
(hold the pending queue), and *workers* (dequeue one task at a time,
execute it, acknowledge success, and retry or dead-letter on failure).
The bookkeeping discipline that makes the system trustworthy is not the
transport — it is the state machine on each task id:

* **enqueue** — a producer registers a named task with frozen args/kwargs.
  The queue pins a content digest over the task body, so a worker can
  verify it received exactly what the producer sent.
* **dequeue** — a worker claims the highest-priority, oldest pending task.
  Claimed tasks are invisible to other workers (at-least-once delivery is
  the broker's contract; exactly-once execution is the task's job, see
  :mod:`exactly_once` for the dedup side).
* **acknowledge** — the worker reports ``ack_success`` with a canonical
  result, or ``ack_failure`` with an error type. Failures retry up to
  ``max_retries`` and are then moved to the dead-letter set — poison
  messages park, they never spin forever.
* **priority** — higher priority dequeues first; FIFO ties. Priority is
  advisory (a starving low-priority task is still a host scheduling
  decision, not a module guarantee).

* **No wall-clock** — every mutation takes a caller-supplied int ``seq``,
  so a run is exactly replayable from the audit trail.
* **Fail-closed** — empty task names, non-canonical args/kwargs results,
  bool seqs, unknown task ids, double completion, and acking a task the
  caller never claimed all raise instead of silently succeeding.

Honest scope: this is *dispatch bookkeeping*, not a worker pool — it never
executes callables, has no network, no timers, no retry backoff (pair with
:mod:`retry_policy` for the delay schedule), and cannot prove a claimed
task actually ran. ``SUCCEEDED`` means "a worker reported a canonical
result", never "the world changed". Results are pinned by digest; the
registry holds the pinned *value* (in-memory) so ``result()`` can return
it — do not treat this module as a durable result store (pair with the
durable audit writer for crash recovery).
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
TASK_QUEUE_VERSION = "task-queue.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.task-queue.v1"

#: Integers beyond this magnitude are refused: the JCS float-loss caveat
#: found in batch 5 (``canonical_json`` silently pins colliding digests for
#: ints that lose precision when decoded as IEEE-754 doubles).
_MAX_SAFE_INT = 2 ** 53


class TaskQueueError(Exception):
    """Base class for all task-queue errors."""


class TaskPayloadError(TaskQueueError):
    """Task name/args/kwargs failed validation (programming error)."""


class ResultNotCanonicalError(TaskQueueError):
    """A result that cannot be canonically pinned was refused."""


class UnknownTaskError(TaskQueueError):
    """A task id is not known to the queue."""


class TaskStateError(TaskQueueError):
    """An operation is invalid for the task's current state."""


class TaskNotCompleteError(TaskQueueError):
    """``result()`` was called before the task succeeded."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TaskQueueError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise TaskQueueError(f"{name} must be non-negative")
    return value


def _check_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise TaskPayloadError(
            f"task_name must be a non-empty str, got {value!r}"
        )
    return value


def _is_finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) \
        and not (isinstance(value, float) and (math.isnan(value) or math.isinf(value)))


def _check_payload_scalar(value: Any, where: str) -> None:
    # Fail-closed payload check: canonicalizable, JSON-shaped, no float loss.
    if isinstance(value, bool):
        return  # bools are canonical
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise TaskPayloadError(f"{where}: int magnitude exceeds 2**53 (JCS float-loss)")
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise TaskPayloadError(f"{where}: NaN/inf floats are not canonicalizable")
        if value.is_integer() and abs(value) > _MAX_SAFE_INT:
            raise TaskPayloadError(f"{where}: integral float exceeds 2**53 (JCS float-loss)")
        return
    if isinstance(value, str) or value is None:
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check_payload_scalar(item, where)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TaskPayloadError(f"{where}: mapping keys must be str, got {type(key).__name__}")
            _check_payload_scalar(item, where)
        return
    raise TaskPayloadError(
        f"{where}: value of type {type(value).__name__} is not canonicalizable"
    )


def _check_args(value: Any) -> tuple:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TaskPayloadError(
            f"args must be a sequence, got {type(value).__name__}"
        )
    checked = tuple(value)
    for i, item in enumerate(checked):
        _check_payload_scalar(item, f"args[{i}]")
    return checked


def _check_kwargs(value: Any) -> tuple:
    if value is None:
        return ()
    if not isinstance(value, Mapping):
        raise TaskPayloadError(f"kwargs must be a mapping, got {type(value).__name__}")
    for key in value:
        if not isinstance(key, str):
            raise TaskPayloadError(
                f"kwargs keys must be str, got {type(key).__name__}"
            )
    items = tuple(sorted(value.items()))
    for key, item in items:
        _check_payload_scalar(item, f"kwargs[{key!r}]")
    return items


def _check_priority(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TaskPayloadError(f"priority must be an int, got {type(value).__name__}")
    return value


def _check_max_retries(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TaskPayloadError(f"max_retries must be an int, got {type(value).__name__}")
    if value < 0:
        raise TaskPayloadError("max_retries must be non-negative")
    return value


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


# Task states. A task moves PENDING -> CLAIMED -> SUCCEEDED, or
# PENDING -> CLAIMED -> FAILED -> PENDING (retry) -> ... -> DEAD_LETTER.
PENDING = "pending"
CLAIMED = "claimed"
SUCCEEDED = "succeeded"
FAILED = "failed"
DEAD_LETTER = "dead-letter"
CANCELLED = "cancelled"


@dataclass(frozen=True)
class TaskRecord:
    """Frozen record of one enqueued task."""

    task_id: str
    task_name: str
    args: tuple
    kwargs: tuple  # sorted (key, value) pairs
    priority: int
    max_retries: int
    attempts: int  # how many times this task has been claimed so far
    state: str
    payload_digest: str
    enqueue_seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": TASK_QUEUE_VERSION,
            "task_id": self.task_id,
            "task_name": self.task_name,
            "args": list(self.args),
            "kwargs": [[k, v] for k, v in self.kwargs],
            "priority": self.priority,
            "max_retries": self.max_retries,
            "attempts": self.attempts,
            "state": self.state,
            "payload_digest": self.payload_digest,
            "enqueue_seq": self.enqueue_seq,
        }


@dataclass(frozen=True)
class DequeuedTask:
    """What a worker receives when it claims a task."""

    task_id: str
    task_name: str
    args: tuple
    kwargs: tuple
    attempt: int  # 1-based: which claim this is
    payload_digest: str
    dequeue_seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": TASK_QUEUE_VERSION,
            "task_id": self.task_id,
            "task_name": self.task_name,
            "args": list(self.args),
            "kwargs": [[k, v] for k, v in self.kwargs],
            "attempt": self.attempt,
            "payload_digest": self.payload_digest,
            "dequeue_seq": self.dequeue_seq,
        }


@dataclass(frozen=True)
class TaskOutcome:
    """Frozen record of a completed (succeeded or dead-lettered) task."""

    task_id: str
    task_name: str
    succeeded: bool
    attempts: int
    result_digest: str | None  # None for dead letters
    error_type: str | None  # set for dead letters
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": TASK_QUEUE_VERSION,
            "task_id": self.task_id,
            "task_name": self.task_name,
            "succeeded": self.succeeded,
            "attempts": self.attempts,
            "result_digest": self.result_digest,
            "error_type": self.error_type,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class RetryDecision:
    """Frozen record of a failure that requeued the task."""

    task_id: str
    attempt: int  # the attempt that just failed (1-based)
    retries_remaining: int
    requeued: bool
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": TASK_QUEUE_VERSION,
            "task_id": self.task_id,
            "attempt": self.attempt,
            "retries_remaining": self.retries_remaining,
            "requeued": self.requeued,
            "seq": self.seq,
        }


class TaskQueue:
    """Celery-style durable task dispatch bookkeeping (single host, in-memory)."""

    def __init__(self, max_retries: int = 3) -> None:
        self._default_max_retries = _check_max_retries(max_retries)
        self._lock = threading.RLock()
        self._counter = 0
        self._records: dict[str, dict[str, Any]] = {}  # task_id -> mutable state
        self._results: dict[str, Any] = {}  # task_id -> pinned result value
        self._pending: list[str] = []  # task ids, ordered by (-priority, enqueue_seq)

    def _lookup(self, task_id: Any) -> dict[str, Any]:
        if not isinstance(task_id, str):
            raise UnknownTaskError(f"task_id must be a str, got {type(task_id).__name__}")
        try:
            return self._records[task_id]
        except KeyError:
            raise UnknownTaskError(f"unknown task_id {task_id!r}") from None

    def _pending_key(self, state: dict[str, Any]) -> tuple:
        return (-state["priority"], state["enqueue_seq"])

    def _resort_pending(self) -> None:
        self._pending.sort(key=lambda tid: self._pending_key(self._records[tid]))

    def enqueue(
        self,
        task_name: str,
        args: Sequence[Any] = (),
        kwargs: Mapping[str, Any] | None = None,
        seq: int = 0,
        priority: int = 0,
        max_retries: int | None = None,
    ) -> TaskRecord:
        """Enqueue a named task. Returns the frozen :class:`TaskRecord`."""
        name = _check_name(task_name)
        checked_args = _check_args(args)
        checked_kwargs = _check_kwargs(kwargs)
        seq = _check_seq(seq)
        priority = _check_priority(priority)
        retries = self._default_max_retries if max_retries is None else _check_max_retries(max_retries)

        with self._lock:
            self._counter += 1
            task_id = f"task-{self._counter}"
            digest = _pin([task_id, name, list(checked_args),
                           [[k, v] for k, v in checked_kwargs],
                           priority, retries, seq])
            state = {
                "task_id": task_id,
                "task_name": name,
                "args": checked_args,
                "kwargs": checked_kwargs,
                "priority": priority,
                "max_retries": retries,
                "attempts": 0,
                "state": PENDING,
                "payload_digest": digest,
                "enqueue_seq": seq,
            }
            self._records[task_id] = state
            self._pending.append(task_id)
            self._resort_pending()
            return self._record_of(state)

    def _record_of(self, state: dict[str, Any]) -> TaskRecord:
        return TaskRecord(
            task_id=state["task_id"],
            task_name=state["task_name"],
            args=state["args"],
            kwargs=state["kwargs"],
            priority=state["priority"],
            max_retries=state["max_retries"],
            attempts=state["attempts"],
            state=state["state"],
            payload_digest=state["payload_digest"],
            enqueue_seq=state["enqueue_seq"],
        )

    def dequeue(self, seq: int = 0) -> DequeuedTask | None:
        """Claim the highest-priority oldest pending task.

        Returns ``None`` when the queue is empty — a worker polling an empty
        queue is normal, not an error (same shape as :mod:`feature_store`'s
        missing-value ``None`` policy).
        """
        seq = _check_seq(seq)
        with self._lock:
            if not self._pending:
                return None
            task_id = self._pending.pop(0)
            state = self._records[task_id]
            state["attempts"] += 1
            state["state"] = CLAIMED
            return DequeuedTask(
                task_id=task_id,
                task_name=state["task_name"],
                args=state["args"],
                kwargs=state["kwargs"],
                attempt=state["attempts"],
                payload_digest=state["payload_digest"],
                dequeue_seq=seq,
            )

    def ack_success(self, task_id: str, result: Any, seq: int = 0) -> TaskOutcome:
        """Report successful completion with a canonicalizable result."""
        seq = _check_seq(seq)
        try:
            _check_payload_scalar(result, "result")
        except TaskPayloadError as exc:
            raise ResultNotCanonicalError(str(exc)) from None
        with self._lock:
            state = self._lookup(task_id)
            if state["state"] != CLAIMED:
                raise TaskStateError(
                    f"task {task_id!r} is {state['state']!r}, not claimed"
                )
            state["state"] = SUCCEEDED
            self._results[task_id] = result
            return TaskOutcome(
                task_id=task_id,
                task_name=state["task_name"],
                succeeded=True,
                attempts=state["attempts"],
                result_digest=_pin([task_id, result]),
                error_type=None,
                seq=seq,
            )

    def ack_failure(
        self, task_id: str, error_type: str, seq: int = 0
    ) -> RetryDecision | TaskOutcome:
        """Report a failed attempt.

        Returns a :class:`RetryDecision` when the task is requeued, or a
        :class:`TaskOutcome` (``succeeded=False``) when it is dead-lettered
        after exhausting ``max_retries``.
        """
        seq = _check_seq(seq)
        if not isinstance(error_type, str) or not error_type:
            raise TaskQueueError(
                f"error_type must be a non-empty str, got {error_type!r}"
            )
        with self._lock:
            state = self._lookup(task_id)
            if state["state"] != CLAIMED:
                raise TaskStateError(
                    f"task {task_id!r} is {state['state']!r}, not claimed"
                )
            retries_used = state["attempts"] - 1
            if retries_used < state["max_retries"]:
                state["state"] = PENDING
                self._pending.append(task_id)
                self._resort_pending()
                return RetryDecision(
                    task_id=task_id,
                    attempt=state["attempts"],
                    retries_remaining=state["max_retries"] - retries_used,
                    requeued=True,
                    seq=seq,
                )
            state["state"] = DEAD_LETTER
            return TaskOutcome(
                task_id=task_id,
                task_name=state["task_name"],
                succeeded=False,
                attempts=state["attempts"],
                result_digest=None,
                error_type=error_type,
                seq=seq,
            )

    def result(self, task_id: str) -> Any:
        """Return the pinned result of a succeeded task."""
        with self._lock:
            state = self._lookup(task_id)
            if state["state"] != SUCCEEDED:
                raise TaskNotCompleteError(
                    f"task {task_id!r} is {state['state']!r}, not succeeded"
                )
            return self._results[task_id]

    def cancel(self, task_id: str, seq: int = 0) -> TaskRecord:
        """Cancel a pending task. Claimed tasks cannot be cancelled."""
        seq = _check_seq(seq)
        with self._lock:
            state = self._lookup(task_id)
            if state["state"] != PENDING:
                raise TaskStateError(
                    f"task {task_id!r} is {state['state']!r}, only pending tasks can be cancelled"
                )
            state["state"] = CANCELLED
            self._pending.remove(task_id)
            return self._record_of(state)

    def pending_count(self) -> int:
        """Number of tasks waiting to be claimed."""
        with self._lock:
            return len(self._pending)

    def record(self, task_id: str) -> TaskRecord:
        """Frozen view of a task's current record."""
        with self._lock:
            return self._record_of(self._lookup(task_id))

    def stats(self) -> dict[str, int]:
        """Counts by state."""
        counts = {
            PENDING: 0, CLAIMED: 0, SUCCEEDED: 0,
            FAILED: 0, DEAD_LETTER: 0, CANCELLED: 0,
        }
        with self._lock:
            for state in self._records.values():
                counts[state["state"]] = counts.get(state["state"], 0) + 1
        return counts


_AUDIT_KINDS = frozenset({
    "task-enqueued", "task-dequeued", "task-succeeded", "task-failed",
    "task-retried", "task-dead-lettered", "task-cancelled", "rejected",
})


def task_queue_audit_event(kind: str, seq: int, task_id: str = "") -> dict[str, Any]:
    """Shape a queue event as an ``audit.ndjson/1``-style record."""
    if kind not in _AUDIT_KINDS:
        raise TaskQueueError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    return {
        "schema": "audit.ndjson/1",
        "event": kind,
        "task_id": task_id,
        "audit_seq": seq,
        "module_version": TASK_QUEUE_VERSION,
        "module_schema": SCHEMA_PIN,
    }


def main() -> None:
    """Self-check: enqueue, priority dequeue, success, retry, dead-letter."""
    q = TaskQueue(max_retries=1)

    low = q.enqueue("low.task", args=(1,), seq=0, priority=0)
    high = q.enqueue("high.task", kwargs={"x": 2}, seq=1, priority=10)
    assert low.task_id == "task-1" and high.task_id == "task-2"
    assert low.payload_digest.startswith("sha256:") and high.payload_digest.startswith("sha256:")
    assert low.payload_digest != high.payload_digest

    got = q.dequeue(seq=2)
    assert got is not None and got.task_id == "task-2" and got.attempt == 1
    assert q.record("task-2").state == CLAIMED

    outcome = q.ack_success("task-2", {"ok": True}, seq=3)
    assert outcome.succeeded and outcome.attempts == 1
    assert outcome.result_digest is not None
    assert q.result("task-2") == {"ok": True}

    got2 = q.dequeue(seq=4)
    assert got2 is not None and got2.task_id == "task-1"
    retry = q.ack_failure("task-1", "ValueError", seq=5)
    assert isinstance(retry, RetryDecision) and retry.requeued
    assert retry.retries_remaining == 1
    assert q.pending_count() == 1

    got3 = q.dequeue(seq=6)
    assert got3 is not None and got3.task_id == "task-1" and got3.attempt == 2
    dead = q.ack_failure("task-1", "ValueError", seq=7)
    assert isinstance(dead, TaskOutcome) and not dead.succeeded
    assert dead.error_type == "ValueError"
    assert q.record("task-1").state == DEAD_LETTER
    assert q.dequeue(seq=8) is None

    try:
        q.result("task-1")
    except TaskNotCompleteError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected TaskNotCompleteError")

    print("task-queue OK: enqueue, priority dequeue, success, retry, dead-letter")


if __name__ == "__main__":
    main()
