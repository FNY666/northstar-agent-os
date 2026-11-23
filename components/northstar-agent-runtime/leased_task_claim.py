"""Lease claim with a fencing token, and a reaper for expired leases.

What was missing
----------------
Read from the code, not assumed:

* ``distributed_lock.py`` owns a fencing token and a lease *shape*
  (``FencingToken``/``LockLease``), and a lock ledger that hands out strictly
  increasing tokens per lock id.  It is a lock ledger: it is not wired to any
  task claim, and nothing in the repo asks it for a task's lease.
* ``job_queue.py`` owns enqueue / dequeue / ack / retry / dead, with backoff
  booking and a dead-letter transition when the retry budget is exhausted.
  Two properties of the *existing* code matter here:
  - ``dequeue(worker_id, queue, seq)`` reserves **the next eligible job in a
    queue**, not a job named by id.  There is no by-id reservation.
  - ``retry()`` counts *executions* (``attempts`` is incremented by
    ``dequeue()``), so a crash requeue would consume the same budget a
    reported failure consumes.
  - **AMENDED 2026-11-23:** ``job_queue.py`` also gained ``dead()`` -- a
    terminal FAILURE, distinct from ``ack()`` (terminal success) and from
    ``retry()`` (a re-dispatch) -- and ``retry_allowed()``, the batch-safe
    form of ``retry()``.  The mirror needs both: a finished task's mirror
    job must not go back to ``ready``, and the reaper's sweep must not be
    abandoned because one task's mirror refused.  See
    ``docs/design/refusal-hold-wiring.md`` §13.
* ``outbox_pattern.py`` owns the transactional outbox state machine
  (``OutboxMessage``/``MessageState``/``OutboxEvent``/``DispatchReport``) with
  store-then-send and at-least-once dispatch.
* ``dead_letter_queue.py`` owns dead-letter bookkeeping: an id is booked once
  and never recycled, and a message can be retried or discarded.
* ``checkpoints.py`` owns turn-boundary checkpoints and lineage selection.  It
  knows nothing about leases.

So, today: a worker that crashes mid-task leaves its queue job in
``reserved`` **forever** -- there is no expiry on a reservation and no
reaper anywhere in the repo (``grep -r "reaper|StaleLease"`` is empty).  And
there is nothing that can reject a write made by a worker whose lease has
already been taken over by somebody else: the queue ledger has no token, so
"the zombie writes" is indistinguishable from "the current worker writes".

This module is the missing wiring.  It adds:

* a **claim** that takes a time-limited lease and a strictly increasing
  fencing token for a task;
* **write-time token checks** -- ``complete`` / ``fail`` / ``heartbeat`` /
  ``save_checkpoint`` / ``release`` all verify the presented token against the
  current token, and a stale holder's write is refused with
  ``StaleLeaseError`` while changing nothing at all;
* a **reaper** that finds expired leases and requeues them, without charging
  the task a backoff delay (a crash is not the task's fault);
* **checkpoint hand-over** -- the new holder resumes from the newest
  checkpoint, and the ledger refuses to move a checkpoint backwards;
* **terminal state + outbox row committed together**, with a stable
  idempotency key ``<task_id>:<event_type>``.

Source (agent-task-runtime, commit ``bbad5e3``) -- verbatim excerpts:

* "认领即在一个 ``BEGIN IMMEDIATE`` 事务里拿限时租约并递增单调 fencing token
  （token 就是认领计数器）。"  Claiming takes a limited-time lease and
  increments a monotonic fencing token inside one ``BEGIN IMMEDIATE``
  transaction; the token *is* the claim counter.
* "``complete / fail / heartbeat / save_checkpoint / release`` 每次写都校验
  当前 token，过期持有者的写以 ``StaleLeaseError`` 拒绝且什么都不改。"
  Every write checks the current token; a stale holder's write is refused
  with ``StaleLeaseError`` and changes nothing.
* "租约收割器（reaper）扫过期租约直接重排队（崩溃不算任务过错，不吃退避
  延迟）；上报的失败才走指数退避。"  The reaper sweeps expired leases
  straight back into the queue -- a crash is not the task's fault and eats no
  backoff delay; only a *reported* failure takes exponential backoff.
* "每步 checkpoint，换人接手从 checkpoint 续跑不重做；终态与 outbox 行同
  事务提交，at-least-once 投递 + 稳定幂等键 ``<task_id>:<event_type>``。"
  Checkpoint every step; a new holder resumes from the checkpoint instead of
  redoing it; the terminal state and the outbox row commit in one
  transaction; at-least-once delivery with a stable idempotency key.

Scope of this slice
-------------------
This module wires **the reaper and the fencing-token claim** between the
existing queue ledger and a lease.  It does **not** port the whole
``agent-task-runtime`` repository.  ``distributed_lock`` /
``outbox_pattern`` / ``dead_letter_queue`` are **read-only
reused**: this module imports their public shapes and never edits them.

**AMENDED 2026-11-23:** ``job_queue`` is no longer read-only.  The mirror
needs two operations the queue ledger did not have -- a terminal FAILURE
(``dead()``) and a batch-safe re-dispatch (``retry_allowed()``) -- and
without them the mirror and the lease ledger disagreed in two measurable
ways.  The reasoning and the measurement are in
``docs/design/refusal-hold-wiring.md`` §13; the queue's version and schema
pins are unchanged.

Two wiring facts forced two design decisions, both recorded in
``docs/design/leased-task-claim.md``:

1. ``JobQueue.dequeue`` reserves by selection, not by id, and this module's
   claim is by task id.  Each task therefore gets its own queue name in the
   shared ``JobQueue`` instance (``task:<task_id>``), so the queue ledger can
   still be the real reservation ledger.
2. ``JobQueue.retry`` counts executions, so a crash would consume the retry
   budget.  The **failure budget is therefore owned by this module** and
   counts *reported failures only*; the queue mirror is given the maximum
   retry budget so it never self-deaths, and exhausted failures are booked
   into ``dead_letter_queue``.

Northstar extensions beyond the source text are marked as such in the design
doc; the source text is quoted verbatim there.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence

from dead_letter_queue import DeadLetterQueue
from distributed_lock import FencingToken
from job_queue import JobQueue
from outbox_pattern import DispatchReport, MessageState, OutboxMessage

#: Version of this module.
LEASED_TASK_CLAIM_VERSION = "leased-task-claim.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.leased-task-claim.v1"

#: Default destination for terminal outbox rows.
DEFAULT_DESTINATION = "task.events"

#: Event type booked for a successful terminal state.
EVENT_COMPLETED = "completed"

#: Event type booked when the failure budget is exhausted.
EVENT_DEAD = "dead"

#: Task states (job_queue-compatible names).
STATE_READY = "ready"
STATE_LEASED = "leased"
STATE_COMPLETED = "completed"
STATE_DEAD = "dead"

#: The queue ledger never self-deaths: this module owns the failure budget.
QUEUE_MAX_RETRIES = 64

_MAX_INT = 2**53 - 1


class LeasedTaskClaimError(Exception):
    """Base class for this module's refusals."""


class UnknownTaskError(LeasedTaskClaimError):
    """The task id was never claimed."""


class LeaseHeldError(LeasedTaskClaimError):
    """The task already has a live lease; a second claim would be a double
    lease on the same task."""


class BackoffError(LeasedTaskClaimError):
    """The task is in backoff after a reported failure and is not eligible
    for a claim yet."""


class TerminalTaskError(LeasedTaskClaimError):
    """The task is already terminal (completed or dead)."""


class StaleLeaseError(LeasedTaskClaimError):
    """The presented fencing token is not the current one, or the lease has
    expired.  The write is refused and nothing is changed."""


class CheckpointOrderError(LeasedTaskClaimError):
    """The checkpoint would move the task's progress backwards."""


class QueueMirrorError(LeasedTaskClaimError):
    """The queue mirror and the lease ledger disagree; the claim is refused
    rather than guessed."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaskLease:
    """A live (or recently dead) claim on a task.

    The shape mirrors ``distributed_lock.LockLease`` (owner, fencing token,
    acquisition and expiry) but the clock is wall-clock seconds rather than a
    logical sequence: a lease has to expire while nobody is looking at it.
    The fencing token *is* the claim counter.
    """

    task_id: str
    worker: str
    fencing_token: FencingToken
    acquired_at: float
    expires_at: float
    ttl_seconds: float
    failures: int = 0
    schema: str = SCHEMA_PIN

    @property
    def token(self) -> int:
        """The fencing token value."""
        return self.fencing_token.token

    def is_expired(self, now: float) -> bool:
        """True when the lease is dead.  Expiry is inclusive: the lease is
        valid *through* ``expires_at``."""
        return now > self.expires_at

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "task_id": self.task_id,
            "worker": self.worker,
            "fencing_token": self.fencing_token.as_dict(),
            "token": self.fencing_token.token,
            "acquired_at": self.acquired_at,
            "expires_at": self.expires_at,
            "ttl_seconds": self.ttl_seconds,
            "failures": self.failures,
        }


@dataclass(frozen=True)
class TaskView:
    """Pure read view of one task's lease-ledger state."""

    task_id: str
    state: str
    worker: str
    token: int
    acquired_at: Optional[float]
    expires_at: Optional[float]
    delay_until: float
    failures: int
    crashes: int
    payload_digest: str
    task: str
    queue_name: str
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class CheckpointRecord:
    """One checkpoint of a task's progress."""

    task_id: str
    step: int
    payload: dict
    token: int
    worker: str
    created_at: float
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class TerminalRecord:
    """A committed terminal state and the outbox row it committed with."""

    task_id: str
    event_type: str
    message_id: str
    token: int
    payload: dict
    destination: str
    created_at: float
    replayed: bool = False
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class FailRecord:
    """The outcome of a reported failure."""

    task_id: str
    token: int
    failures: int
    max_failures: int
    delay_seconds: float
    state: str
    reason: str
    dead_letter_id: Optional[str] = None
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class ReleasedRecord:
    """A voluntarily released lease."""

    task_id: str
    token: int
    worker: str
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class ReapedLease:
    """One lease the reaper swept back into the queue."""

    task_id: str
    worker: str
    token: int
    expired_at: float
    requeued_at: float
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class OutboxRow:
    """One row of the transactional outbox."""

    message_id: str
    task_id: str
    event_type: str
    destination: str
    payload: dict
    state: str
    attempts: int
    created_at: float
    schema: str = SCHEMA_PIN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_text(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ValueError(f"{name} must be non-empty")
    return text


def _check_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    return value


def _check_ttl(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"ttl must be a number, got {type(value).__name__}")
    ttl = float(value)
    if not math.isfinite(ttl) or ttl <= 0:
        raise ValueError("ttl must be a positive finite number of seconds")
    return ttl


def digest_of(text: str) -> str:
    """``sha256:`` + hex digest of ``text`` -- the digest shape used by
    ``job_queue`` and ``dead_letter_queue`` for payloads."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def idempotency_key(task_id: str, event_type: str) -> str:
    """The stable idempotency key ``<task_id>:<event_type>``."""
    return f"{task_id}:{event_type}"


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"payload is not JSON-serialisable: {exc}") from None


# ---------------------------------------------------------------------------
# Lease ledger (SQLite)
# ---------------------------------------------------------------------------

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ltc_task (
        task_id        TEXT PRIMARY KEY,
        task           TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        queue_name     TEXT NOT NULL,
        state          TEXT NOT NULL,
        worker         TEXT NOT NULL DEFAULT '',
        token          INTEGER NOT NULL DEFAULT 0,
        acquired_at    REAL,
        expires_at     REAL,
        delay_until    REAL NOT NULL DEFAULT 0,
        failures       INTEGER NOT NULL DEFAULT 0,
        crashes        INTEGER NOT NULL DEFAULT 0,
        last_step      INTEGER NOT NULL DEFAULT 0,
        terminal_event TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ltc_checkpoint (
        task_id    TEXT NOT NULL,
        step       INTEGER NOT NULL,
        payload    TEXT NOT NULL,
        token      INTEGER NOT NULL,
        worker     TEXT NOT NULL,
        created_at REAL NOT NULL,
        PRIMARY KEY (task_id, step)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ltc_outbox (
        message_id  TEXT PRIMARY KEY,
        task_id     TEXT NOT NULL,
        event_type  TEXT NOT NULL,
        destination TEXT NOT NULL,
        payload     TEXT NOT NULL,
        state       TEXT NOT NULL,
        attempts    INTEGER NOT NULL DEFAULT 0,
        created_at  REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ltc_audit (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        kind     TEXT NOT NULL,
        task_id  TEXT NOT NULL,
        detail   TEXT NOT NULL,
        created_at REAL NOT NULL
    )
    """,
)


class _Store:
    """SQLite-backed lease ledger.

    Every mutation runs inside one ``BEGIN IMMEDIATE`` transaction, so a
    claim, its fencing token increment and the state change either all
    happen or none of them do.  The connection is opened with
    ``isolation_level=None`` so transactions are explicit.
    """

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._conn = sqlite3.connect(
            path or ":memory:", isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._conn:
            for statement in _SCHEMA:
                self._conn.execute(statement)

    # -- transactions ---------------------------------------------------

    @contextlib.contextmanager
    def transaction(self):
        """One ``BEGIN IMMEDIATE`` transaction."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def read(self, statement: str, params: Sequence[Any] = ()) -> list:
        with self._lock:
            return list(self._conn.execute(statement, tuple(params)))

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    # -- audit ----------------------------------------------------------

    def audit(self, conn: sqlite3.Connection, kind: str, task_id: str,
              detail: Mapping[str, Any]) -> None:
        conn.execute(
            "INSERT INTO ltc_audit (kind, task_id, detail, created_at) "
            "VALUES (?, ?, ?, ?)",
            (kind, task_id, _canonical_json(dict(detail)), time.time()),
        )

    def audit_log(self) -> tuple:
        rows = self.read(
            "SELECT kind, task_id, detail, created_at FROM ltc_audit "
            "ORDER BY id"
        )
        return tuple(
            {
                "kind": row["kind"],
                "task_id": row["task_id"],
                "detail": json.loads(row["detail"]),
                "created_at": row["created_at"],
                "schema": SCHEMA_PIN,
            }
            for row in rows
        )


# ---------------------------------------------------------------------------
# The claim manager
# ---------------------------------------------------------------------------


class LeasedTaskClaim:
    """Lease a task with a fencing token; reap the dead; refuse the zombies.

    The manager owns three ledgers, each reused from an existing module:

    * the **lease ledger** (this module's SQLite store) -- the task's state,
      its current fencing token, its checkpoints and its outbox rows;
    * the **queue mirror** (``job_queue.JobQueue``) -- the real reservation
      ledger.  Each task lives in its own queue (``task:<task_id>``) because
      ``JobQueue.dequeue`` reserves by selection, not by id;
    * the **dead-letter ledger** (``dead_letter_queue.DeadLetterQueue``) --
      where a task goes when its *reported* failure budget is exhausted.

    **The mirror and the lease ledger move together.**  Every mirror
    write happens inside the transaction that writes the lease ledger, so
    a refusal by the mirror's own gate rolls the lease write back rather
    than leaving the two ledgers disagreeing -- and a *terminal* task
    moves its mirror job to the queue's terminal state (``done`` for a
    completion, ``dead`` for an exhausted budget) rather than back to
    ``ready``, which would advertise a finished work item as available.

    Every public mutator takes a ``now`` argument (wall-clock seconds) so
    tests are deterministic; the default is ``time.time()``.
    """

    def __init__(
        self,
        *,
        path: str = ":memory:",
        queue: Optional[JobQueue] = None,
        dead_letters: Optional[DeadLetterQueue] = None,
        max_failures: int = 3,
        base_backoff_seconds: float = 1.0,
        backoff_factor: float = 2.0,
        max_backoff_seconds: float = 300.0,
        clock: Callable[[], float] = time.time,
        refusal_gate: Optional[Any] = None,
    ) -> None:
        if isinstance(max_failures, bool) or not isinstance(max_failures, int):
            raise ValueError("max_failures must be an int")
        if max_failures < 1 or max_failures > 64:
            raise ValueError("max_failures must be in [1, 64]")
        self._store = _Store(path)
        self._queue = queue if queue is not None else JobQueue()
        self._dead_letters = (
            dead_letters if dead_letters is not None else DeadLetterQueue()
        )
        self.max_failures = max_failures
        self.base_backoff_seconds = float(base_backoff_seconds)
        self.backoff_factor = float(backoff_factor)
        self.max_backoff_seconds = float(max_backoff_seconds)
        self._clock = clock
        self._seq = 0
        #: The optional **refusal gate** (see
        #: ``refusal_hold_wiring.RefusalHoldQueueGate``).  When one is
        #: installed, a task whose re-dispatch is covered by a recorded
        #: refusal is NOT re-dispatched: ``fail()`` refuses the write
        #: that puts it back to ``ready``, and ``claim()`` refuses the
        #: write that takes it out of ``ready`` and offers it to a
        #: worker.  Either way the task stays where it is.
        #:
        #: The gate is **duck-typed**: this module does not import the
        #: wiring (the wiring imports the hold, and the hold must not
        #: drag the lease ledger in).  It must offer
        #: ``require_task_allowed(task_id, action, now=...)``.
        self._refusal_gate = refusal_gate

    @property
    def refusal_gate(self) -> Optional[Any]:
        """The installed refusal gate, if any."""
        return self._refusal_gate

    def set_refusal_gate(self, gate: Optional[Any]) -> None:
        """Install (or remove) the refusal gate.

        The gate is asked about the task's **action identity**, which the
        task already carries: the ``task`` column of ``ltc_task`` is the
        work item's action, so no schema change is needed.
        """
        self._refusal_gate = gate

    def _require_refusal_allows(self, task_id: str, action: str,
                                now: float) -> None:
        """Ask the refusal gate, if one is installed.

        Called **inside** the caller's transaction, immediately before the
        ``UPDATE`` that flips the task's state.  A refusal raises, so the
        transaction rolls back and the task keeps its state, its failure
        count and its delay.

        Two callers use this raising form, and they are the two that
        report **one** task for **one** call:

        * :meth:`fail` -- the worker reports a failure, and the task goes
          back to ``ready``;
        * :meth:`claim` -- the task goes **out** of ``ready`` and the
          action is offered to a worker.

        :meth:`reap` does not use it: it sweeps a batch and must not
        abandon the sweep, so it asks the boolean form instead (see
        :meth:`_refusal_allows_reap`).
        """
        gate = self._refusal_gate
        if gate is None:
            return
        require = getattr(gate, "require_task_allowed", None)
        if not callable(require):
            raise TypeError(
                "the refusal gate must offer require_task_allowed(task_id, "
                f"action, now=...), got {type(gate).__name__}"
            )
        require(task_id, action, now=now)

    def _refusal_allows_reap(self, task_id: str, action: str,
                              now: float) -> bool:
        """True when the refusal gate allows this task to be re-dispatched.

        The crash path asks a **boolean** question, not the raising one
        that :meth:`fail` asks.  The difference is deliberate:

        * ``fail()`` reports ONE failure for ONE task, so a refusal can
          raise -- the caller asked about that task and nothing else.
        * ``reap()`` sweeps a **batch** of expired leases.  A raise here
          would abandon the whole sweep: one refused task would stop
          every other expired lease from being requeued, which is a
          denial of service the refusal never asked for.

        So the refusal is caught and turned into "not allowed".  A gate
        that cannot answer at all -- an unreadable store, a tampered row
        -- is also "not allowed", because the hold fails closed.

        The gate is duck-typed, as in :meth:`_require_refusal_allows`,
        and a gate that does not offer the boolean method falls back to
        the raising one: a raise is treated as "not allowed".
        """
        gate = self._refusal_gate
        if gate is None:
            return True
        allows = getattr(gate, "task_allowed", None)
        if callable(allows):
            try:
                return bool(allows(task_id, action, now=now))
            except Exception:
                # Fail closed: a gate that cannot answer blocks.
                return False
        require = getattr(gate, "require_task_allowed", None)
        if not callable(require):
            raise TypeError(
                "the refusal gate must offer task_allowed(task_id, action, "
                f"now=...) or require_task_allowed(task_id, action, now=...), "
                f"got {type(gate).__name__}"
            )
        try:
            require(task_id, action, now=now)
        except Exception:
            return False
        return True

    # -- helpers ---------------------------------------------------------

    def _next_seq(self) -> int:
        """A strictly increasing sequence for the reused ledgers."""
        self._seq += 1
        return self._seq

    @staticmethod
    def queue_name_for(task_id: str) -> str:
        """The queue-mirror queue name of a task.

        ``JobQueue.dequeue`` reserves *the next eligible job in a queue*, so
        a by-task claim needs a by-task queue.  The name is truncated to the
        128 characters ``job_queue`` allows.
        """
        name = f"task:{task_id}"
        return name[:128]

    def _row(self, task_id: str) -> Optional[sqlite3.Row]:
        rows = self._store.read(
            "SELECT * FROM ltc_task WHERE task_id = ?", (task_id,)
        )
        return rows[0] if rows else None

    def _require_row(self, task_id: str) -> sqlite3.Row:
        row = self._row(task_id)
        if row is None:
            raise UnknownTaskError(f"unknown task_id: {task_id}")
        return row

    def _backoff_for(self, failures: int) -> float:
        """Exponential backoff for a *reported* failure.

        ``base * factor ** (failures - 1)``, capped.  The crash path never
        calls this: a crash is not the task's fault and eats no delay.
        """
        delay = self.base_backoff_seconds * (
            self.backoff_factor ** max(0, failures - 1)
        )
        return min(delay, self.max_backoff_seconds)

    # -- read views -----------------------------------------------------

    def task(self, task_id: str) -> Optional[TaskView]:
        """Pure read view of a task's lease-ledger state."""
        row = self._row(task_id)
        if row is None:
            return None
        return TaskView(
            task_id=row["task_id"],
            state=row["state"],
            worker=row["worker"],
            token=row["token"],
            acquired_at=row["acquired_at"],
            expires_at=row["expires_at"],
            delay_until=row["delay_until"],
            failures=row["failures"],
            crashes=row["crashes"],
            payload_digest=row["payload_digest"],
            task=row["task"],
            queue_name=row["queue_name"],
        )

    def checkpoint(self, task_id: str) -> Optional[CheckpointRecord]:
        """The newest checkpoint of a task, or ``None``."""
        rows = self._store.read(
            "SELECT * FROM ltc_checkpoint WHERE task_id = ? "
            "ORDER BY step DESC LIMIT 1",
            (task_id,),
        )
        if not rows:
            return None
        row = rows[0]
        return CheckpointRecord(
            task_id=row["task_id"],
            step=row["step"],
            payload=json.loads(row["payload"]),
            token=row["token"],
            worker=row["worker"],
            created_at=row["created_at"],
        )

    def outbox_rows(self, task_id: str) -> tuple:
        """Every outbox row of a task, oldest first."""
        rows = self._store.read(
            "SELECT * FROM ltc_outbox WHERE task_id = ? "
            "ORDER BY created_at, message_id",
            (task_id,),
        )
        return tuple(
            OutboxRow(
                message_id=row["message_id"],
                task_id=row["task_id"],
                event_type=row["event_type"],
                destination=row["destination"],
                payload=json.loads(row["payload"]),
                state=row["state"],
                attempts=row["attempts"],
                created_at=row["created_at"],
            )
            for row in rows
        )

    def audit_log(self) -> tuple:
        """The append-only audit trail of this manager."""
        return self._store.audit_log()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._store.close()

    # -- task registration ------------------------------------------------

    def enqueue_task(self, task_id: str, task: str, payload: str = "") -> TaskView:
        """Register a task and put it in the queue mirror, ready to claim.

        The task starts in ``ready`` with token ``0``.  The first claim
        makes the token ``1`` -- the token is the claim counter.
        """
        task_id = _check_text(task_id, "task_id")
        task = _check_text(task, "task")
        if len(task_id) > 256:
            raise ValueError("task_id exceeds 256 chars")
        if len(task) > 256:
            raise ValueError("task exceeds 256 chars")
        queue_name = self.queue_name_for(task_id)
        digest = digest_of(payload)
        with self._store.transaction() as conn:
            existing = conn.execute(
                "SELECT task_id FROM ltc_task WHERE task_id = ?", (task_id,)
            ).fetchone()
            if existing is not None:
                raise LeasedTaskClaimError(
                    f"task already registered: {task_id}"
                )
            conn.execute(
                "INSERT INTO ltc_task (task_id, task, payload_digest, "
                "queue_name, state, worker, token, delay_until, failures, "
                "crashes, last_step) VALUES (?, ?, ?, ?, ?, '', 0, 0, 0, 0, 0)",
                (task_id, task, digest, queue_name, STATE_READY),
            )
            self._store.audit(
                conn, "task.enqueued", task_id,
                {"task": task, "payload_digest": digest, "queue": queue_name},
            )
        self._queue.enqueue(
            job_id=task_id,
            queue=queue_name,
            task=task,
            payload_digest=digest,
            seq=self._next_seq(),
            max_retries=QUEUE_MAX_RETRIES,
        )
        return self.task(task_id)  # type: ignore[return-value]

    # -- the claim ------------------------------------------------------

    def claim(self, task_id: str, worker: str, ttl: float,
              now: Optional[float] = None) -> TaskLease:
        """Take a limited-time lease on a task with a new fencing token.

        The fencing token is incremented inside the same ``BEGIN IMMEDIATE``
        transaction that installs the lease, so the token is strictly
        increasing per task and never reverts.  A task with a live lease
        cannot be claimed again (``LeaseHeldError``); a task whose lease has
        expired *is* claimable, and the takeover is the moment the previous
        holder's writes start being refused.

        **A recorded refusal blocks the claim.**  This is the path that
        actually **offers the action to somebody**: the task leaves
        ``ready`` and a worker gets it.  The other three paths
        (``fail()``, ``release()``, ``reap()``) put a task *back* to
        ``ready``; this one takes it *out*, and it is the moment the
        refused action is offered again.

        The check runs inside the transaction, immediately before the
        ``UPDATE`` that installs the lease, so a refusal and the claim
        cannot interleave, and a refused claim leaves the task exactly
        as it was -- ``ready`` with no worker, or ``leased`` with its
        previous holder.

        Measured 2026-11-23, before this check: a refusal recorded
        against the lease namespace was honoured by ``reap()`` but not
        by ``claim()``, so a crashed holder's task was handed to a new
        worker anyway.
        """
        task_id = _check_text(task_id, "task_id")
        worker = _check_text(worker, "worker")
        ttl = _check_ttl(ttl)
        now = self._clock() if now is None else float(now)

        with self._store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM ltc_task WHERE task_id = ?", (task_id,)
            ).fetchone()
            if row is None:
                raise UnknownTaskError(f"unknown task_id: {task_id}")
            if row["state"] in (STATE_COMPLETED, STATE_DEAD):
                raise TerminalTaskError(
                    f"task {task_id} is {row['state']}: terminal"
                )
            if row["state"] == STATE_LEASED:
                if float(now) <= float(row["expires_at"]):
                    raise LeaseHeldError(
                        f"task {task_id} is leased by {row['worker']} "
                        f"until {row['expires_at']}"
                    )
                # An expired lease: the previous holder is a zombie from
                # here on.  Count the crash exactly once.
                conn.execute(
                    "UPDATE ltc_task SET crashes = crashes + 1 WHERE task_id = ?",
                    (task_id,),
                )
                self._store.audit(
                    conn, "lease.expired", task_id,
                    {"worker": row["worker"], "token": row["token"]},
                )
            if float(row["delay_until"]) > float(now):
                raise BackoffError(
                    f"task {task_id} is in backoff until {row['delay_until']}"
                )

            token = int(row["token"]) + 1
            expires_at = float(now) + ttl
            # The refusal gate is asked BEFORE the lease is installed, so
            # a refusal leaves the task exactly where it was -- and
            # AFTER the terminal/live-lease checks, so a task that is not
            # claimable at all still fails for its own reason.
            self._require_refusal_allows(task_id, str(row["task"]), now)
            conn.execute(
                "UPDATE ltc_task SET state = ?, worker = ?, token = ?, "
                "acquired_at = ?, expires_at = ? WHERE task_id = ?",
                (STATE_LEASED, worker, token, float(now), expires_at, task_id),
            )
            self._store.audit(
                conn, "lease.claimed", task_id,
                {"worker": worker, "token": token, "expires_at": expires_at},
            )
            # The queue mirror is the reservation ledger: the task's job
            # must be dequeued (reserved) by this worker.
            self._mirror_reserve(task_id, row["queue_name"], worker)
            lease = TaskLease(
                task_id=task_id,
                worker=worker,
                fencing_token=FencingToken(
                    lock_id=task_id, token=token, owner=worker
                ),
                acquired_at=float(now),
                expires_at=expires_at,
                ttl_seconds=ttl,
                failures=int(row["failures"]),
            )
        return lease

    def _mirror_reserve(self, task_id: str, queue_name: str, worker: str) -> None:
        """Reserve the task's job in the queue mirror.

        If a previous holder reserved the job and then died, the job is
        still ``reserved`` in the queue ledger; it is retried back to
        ``ready`` (no delay -- a crash is not a fault) before being
        dequeued by the new holder.
        """
        view = self._queue.job(task_id)
        if view is None:
            raise QueueMirrorError(
                f"queue mirror has no job for task {task_id}"
            )
        if view.state == "reserved":
            self._queue.retry(task_id, self._next_seq(), delay_seqs=0)
        elif view.state != "ready":
            raise QueueMirrorError(
                f"queue mirror job for {task_id} is {view.state}"
            )
        reserved = self._queue.dequeue(worker, queue_name, self._next_seq())
        if reserved is None or reserved.job_id != task_id:
            raise QueueMirrorError(
                f"queue mirror refused to reserve {task_id}"
            )

    def _mirror_release(self, task_id: str) -> None:
        """Return the task's job to ``ready`` in the queue mirror.

        The mirror's own ``retry()`` consults the queue-side refusal
        gate, so a refusal recorded in the **queue** namespace refuses
        this bookkeeping.  That refusal is **not** swallowed here: the
        caller is told, and the caller is the one that decides what a
        refused re-dispatch means for the lease ledger.
        """
        view = self._queue.job(task_id)
        if view is None:
            raise QueueMirrorError(
                f"queue mirror has no job for task {task_id}"
            )
        if view.state == "reserved":
            self._queue.retry(task_id, self._next_seq(), delay_seqs=0)

    def _mirror_release_allowed(self, task_id: str) -> bool:
        """The **batch-safe** form of :meth:`_mirror_release`.

        A caller that sweeps a **batch** of tasks must not abandon the
        sweep because one task's mirror refused the re-dispatch.  So
        this form asks the **boolean** question and returns ``False``
        for "not re-dispatched".

        ``False`` means the mirror job stays ``reserved`` -- the work
        item is not offered again -- which is exactly what a refusal
        is for.
        """
        view = self._queue.job(task_id)
        if view is None:
            raise QueueMirrorError(
                f"queue mirror has no job for task {task_id}"
            )
        if view.state != "reserved":
            return True
        record = self._queue.retry_allowed(
            task_id, self._next_seq(), delay_seqs=0
        )
        return record is not None

    def _mirror_terminal(self, task_id: str, dead: bool = False) -> None:
        """Move the task's job to its **terminal** mirror state.

        A task that is ``completed`` in the lease ledger is ``done`` in
        the mirror; a task that is ``dead`` is ``dead`` in the mirror.

        This used to be a ``_mirror_release()`` -- a ``retry()`` -- which
        put the job back to ``ready``.  That is the **re-dispatch**
        operation: it says "this work item is available again".  For a
        finished work item that is a lie, and it had an observable
        consequence: the queue's own ``dequeue`` handed out the job of
        a **completed** task.

        Measured 2026-11-23, before this fix:

            === a COMPLETED task's mirror job goes back to 'ready' ===
              mirror state after complete(): ready
              ledger state: completed
            === so the mirror can DEQUEUE a completed task's job ===
              dequeue -> t1

        The lease side then refused the re-claim with
        ``TerminalTaskError``, so the work was not re-run -- but the
        mirror advertised a finished work item as available, and the
        queue is the ledger the dispatcher reads.

        So the terminal transition is the queue's OWN terminal
        operation: ``ack()`` for a success, ``dead()`` for a failure.

        **A recorded refusal does not block this.**  A refusal is
        about the **re-dispatch**: it says the work item may not be
        offered again.  A job being *withdrawn* is not being offered
        again.  So the terminal transition does not consult the gate --
        exactly as ``ack()`` does not.  A refusal that could keep a
        finished work item in the queue forever would be the
        refusal's own denial of service.
        """
        view = self._queue.job(task_id)
        if view is None:
            raise QueueMirrorError(
                f"queue mirror has no job for task {task_id}"
            )
        if view.state != "reserved":
            # Already terminal (or never reserved): nothing to do.
            return
        seq = self._next_seq()
        if dead:
            self._queue.dead(task_id, seq)
        else:
            self._queue.ack(task_id, seq)

    # -- the write-time token check --------------------------------------

    def _check_token(self, conn: sqlite3.Connection, task_id: str,
                     token: int, now: float) -> sqlite3.Row:
        """Refuse a write whose token is not the current one.

        A write is refused when the presented token is not the task's
        current token (a zombie or an old holder), and when the lease has
        expired (the holder is late -- its lease was taken over).  In both
        cases ``StaleLeaseError`` is raised and the caller changes nothing.
        """
        row = conn.execute(
            "SELECT * FROM ltc_task WHERE task_id = ?", (task_id,)
        ).fetchone()
        if row is None:
            raise UnknownTaskError(f"unknown task_id: {task_id}")
        token = _check_int(token, "token")
        if row["state"] != STATE_LEASED:
            raise StaleLeaseError(
                f"task {task_id} is {row['state']}: no live lease to write under"
            )
        if int(row["token"]) != token:
            raise StaleLeaseError(
                f"stale fencing token {token} for task {task_id}: "
                f"current token is {row['token']}"
            )
        if float(now) > float(row["expires_at"]):
            raise StaleLeaseError(
                f"lease for task {task_id} expired at {row['expires_at']}: "
                f"now is {now}"
            )
        return row

    # -- the write paths --------------------------------------------------

    def heartbeat(self, task_id: str, token: int,
                  now: Optional[float] = None,
                  extend_seconds: float = 0.0) -> TaskLease:
        """Extend a live lease.  A stale token or an expired lease is refused.

        The expiry is *extended*, never shortened: ``extend_seconds`` of
        ``0`` keeps the current expiry.
        """
        task_id = _check_text(task_id, "task_id")
        extend = float(extend_seconds)
        if extend < 0:
            raise ValueError("extend_seconds must not be negative")
        now = self._clock() if now is None else float(now)
        with self._store.transaction() as conn:
            row = self._check_token(conn, task_id, token, now)
            expires_at = float(row["expires_at"])
            if extend:
                expires_at = max(expires_at, float(now)) + extend
            conn.execute(
                "UPDATE ltc_task SET expires_at = ? WHERE task_id = ?",
                (expires_at, task_id),
            )
            self._store.audit(
                conn, "lease.heartbeat", task_id,
                {"token": int(token), "expires_at": expires_at},
            )
            return TaskLease(
                task_id=task_id,
                worker=row["worker"],
                fencing_token=FencingToken(
                    lock_id=task_id, token=int(token), owner=row["worker"]
                ),
                acquired_at=float(row["acquired_at"]),
                expires_at=expires_at,
                ttl_seconds=expires_at - float(row["acquired_at"]),
                failures=int(row["failures"]),
            )

    def save_checkpoint(self, task_id: str, token: int, step: int,
                        payload: Mapping[str, Any],
                        now: Optional[float] = None) -> CheckpointRecord:
        """Record progress for the current holder.

        The checkpoint must not move the task *backwards*: a checkpoint at a
        step lower than the newest one is refused
        (``CheckpointOrderError``), and re-saving the same step overwrites
        it (the same step redone with different data is a correction, not a
        rewind).
        """
        task_id = _check_text(task_id, "task_id")
        step = _check_int(step, "step")
        if step < 0:
            raise ValueError("step must be non-negative")
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")
        body = _canonical_json(dict(payload))
        now = self._clock() if now is None else float(now)
        with self._store.transaction() as conn:
            row = self._check_token(conn, task_id, token, now)
            last_step = int(row["last_step"])
            if step < last_step:
                raise CheckpointOrderError(
                    f"checkpoint step {step} is behind step {last_step} "
                    f"for task {task_id}"
                )
            conn.execute(
                "INSERT INTO ltc_checkpoint (task_id, step, payload, token, "
                "worker, created_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(task_id, step) DO UPDATE SET payload = excluded.payload, "
                "token = excluded.token, worker = excluded.worker, "
                "created_at = excluded.created_at",
                (task_id, step, body, int(token), row["worker"], float(now)),
            )
            conn.execute(
                "UPDATE ltc_task SET last_step = ? WHERE task_id = ?",
                (step, task_id),
            )
            self._store.audit(
                conn, "checkpoint.saved", task_id,
                {"step": step, "token": int(token)},
            )
            return CheckpointRecord(
                task_id=task_id,
                step=step,
                payload=dict(payload),
                token=int(token),
                worker=row["worker"],
                created_at=float(now),
            )

    def complete(self, task_id: str, token: int,
                 payload: Optional[Mapping[str, Any]] = None,
                 now: Optional[float] = None,
                 destination: str = DEFAULT_DESTINATION) -> TerminalRecord:
        """Commit the terminal state and its outbox row together.

        The task's terminal state and the ``<task_id>:completed`` outbox row
        are written in **one transaction**: either both exist or neither
        does.  The idempotency key is ``<task_id>:<event_type>``, so a
        replay of the same terminal state finds the row already there and
        does not book a second one.
        """
        task_id = _check_text(task_id, "task_id")
        body = dict(payload or {})
        now = self._clock() if now is None else float(now)
        message_id = idempotency_key(task_id, EVENT_COMPLETED)
        with self._store.transaction() as conn:
            self._check_token(conn, task_id, token, now)
            existing = conn.execute(
                "SELECT * FROM ltc_outbox WHERE message_id = ?", (message_id,)
            ).fetchone()
            replayed = existing is not None
            if not replayed:
                conn.execute(
                    "INSERT INTO ltc_outbox (message_id, task_id, event_type, "
                    "destination, payload, state, attempts, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                    (message_id, task_id, EVENT_COMPLETED, destination,
                     _canonical_json(body), MessageState.PENDING.value, float(now)),
                )
            conn.execute(
                "UPDATE ltc_task SET state = ?, worker = '' WHERE task_id = ?",
                (STATE_COMPLETED, task_id),
            )
            self._store.audit(
                conn, "task.completed", task_id,
                {"token": int(token), "message_id": message_id,
                 "replayed": replayed},
            )
            # The task is FINISHED, so the mirror's job is finished too:
            # ``ack()`` moves it to ``done``.  It used to be a
            # ``_mirror_release()``, which put the job back to ``ready`` --
            # the queue then handed out a completed task's job.
            #
            # The call is INSIDE the transaction, so the two ledgers
            # move together: a mirror that refuses leaves the ledger
            # alone rather than leaving the two out of step.
            self._mirror_terminal(task_id, dead=False)
        return TerminalRecord(
            task_id=task_id,
            event_type=EVENT_COMPLETED,
            message_id=message_id,
            token=int(token),
            payload=body,
            destination=destination,
            created_at=float(now),
            replayed=replayed,
        )

    def fail(self, task_id: str, token: int, reason: str = "",
             now: Optional[float] = None) -> FailRecord:
        """Report a failure: backoff, or the dead letter when the budget is out.

        A *reported* failure is the task's fault, so it takes exponential
        backoff: the task becomes eligible again at
        ``now + base * factor ** (failures - 1)``.  When the failure budget
        is exhausted the task is terminal (``dead``) and a message is booked
        into the dead-letter ledger with the stable id
        ``<task_id>:dead``.

        The crash path (``reap``) never comes here, which is exactly the
        distinction the source text draws: a crash eats no backoff.

        **A recorded refusal blocks the re-dispatch.**  When a refusal
        gate is installed and a refusal covers this task's action, the
        write is refused: the task does not go back to ``ready``, its
        failure count does not advance, and no backoff is booked.  The
        check runs inside the transaction, immediately before the
        ``UPDATE``, so a refusal and the re-dispatch cannot interleave.
        """
        task_id = _check_text(task_id, "task_id")
        now = self._clock() if now is None else float(now)
        with self._store.transaction() as conn:
            row = self._check_token(conn, task_id, token, now)
            failures = int(row["failures"]) + 1
            dead = failures >= self.max_failures
            delay = 0.0 if dead else self._backoff_for(failures)
            self._require_refusal_allows(task_id, str(row["task"]), now)
            conn.execute(
                "UPDATE ltc_task SET state = ?, worker = '', failures = ?, "
                "delay_until = ? WHERE task_id = ?",
                (STATE_DEAD if dead else STATE_READY, failures,
                 float(now) + delay, task_id),
            )
            self._store.audit(
                conn, "task.failed", task_id,
                {"token": int(token), "failures": failures,
                 "delay_seconds": delay, "dead": dead, "reason": reason},
            )
            # The mirror's release is INSIDE the transaction, so a
            # refusal by the mirror's own gate rolls this write back:
            # the task keeps its lease, its failure count and its
            # delay, and no ``task.failed`` row is written.
            if not dead:
                self._mirror_release(task_id)
        if dead:
            message_id = idempotency_key(task_id, EVENT_DEAD)
            self._dead_letters.enqueue(
                msg_id=message_id,
                payload_digest=digest_of(_canonical_json(
                    {"task_id": task_id, "reason": reason}
                )),
                seq=self._next_seq(),
                reason=reason or "failure budget exhausted",
            )
            with self._store.transaction() as conn:
                conn.execute(
                    "INSERT INTO ltc_outbox (message_id, task_id, event_type, "
                    "destination, payload, state, attempts, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 0, ?) "
                    "ON CONFLICT(message_id) DO NOTHING",
                    (message_id, task_id, EVENT_DEAD, DEFAULT_DESTINATION,
                     _canonical_json({"task_id": task_id, "reason": reason}),
                     MessageState.PENDING.value, float(now)),
                )
                self._store.audit(
                    conn, "task.dead", task_id,
                    {"token": int(token), "failures": failures,
                     "message_id": message_id},
                )
                # A task whose failure budget is exhausted is FINISHED,
                # so its mirror job is ``dead`` -- not ``ready``.  The
                # call is INSIDE the transaction, so the two ledgers
                # move together.
                self._mirror_terminal(task_id, dead=True)
        return FailRecord(
            task_id=task_id,
            token=int(token),
            failures=failures,
            max_failures=self.max_failures,
            delay_seconds=delay,
            state=STATE_DEAD if dead else STATE_READY,
            reason=reason,
            dead_letter_id=(
                idempotency_key(task_id, EVENT_DEAD) if dead else None
            ),
        )

    def release(self, task_id: str, token: int,
                now: Optional[float] = None) -> ReleasedRecord:
        """Give up a live lease voluntarily.

        The task returns to ``ready`` with no backoff: releasing is not a
        failure.  A stale token is refused with ``StaleLeaseError``.

        **A recorded refusal blocks the re-dispatch here too.**  This is
        the third path that puts a task back to ``ready``, and the
        cheapest one to reach -- a worker gives up its lease without a
        failure record, a crash or a backoff.  The question is not
        whether the work item failed; it is whether the work item may be
        **offered again**, and a refusal says no by any route.

        The check runs inside the transaction, immediately before the
        ``UPDATE``, so a refusal and the release cannot interleave.

        **The mirror's release runs INSIDE the transaction too.**
        Measured 2026-11-23, before this fix: the mirror call was
        AFTER the transaction committed, so a refusal recorded in the
        **queue** namespace -- the mirror's own gate -- raised after
        the lease ledger had already said ``ready``:

            release RAISED: RefusalRefusedError
            ledger state: ready
            mirror state: reserved
            audit kinds: ['task.enqueued', 'lease.claimed', 'lease.released']

        Three things were wrong at once: the two ledgers disagreed, the
        audit trail recorded a release that had been refused, and the
        task was **stuck** -- the ledger said ``ready`` (so the reaper
        found no lease to sweep) while the mirror said ``reserved`` (so
        the claim refused to reserve it again).

        Moving the mirror call inside the transaction fixes all three
        at once: a refused mirror release rolls the lease write back,
        so the task stays **leased** by the same worker, no
        ``lease.released`` row is written, and the mirror stays
        ``reserved`` -- which is the state a leased task's mirror job
        is in.  The worker can still finish the work it was doing.
        """
        task_id = _check_text(task_id, "task_id")
        now = self._clock() if now is None else float(now)
        with self._store.transaction() as conn:
            row = self._check_token(conn, task_id, token, now)
            self._require_refusal_allows(task_id, str(row["task"]), now)
            conn.execute(
                "UPDATE ltc_task SET state = ?, worker = '', expires_at = ? "
                "WHERE task_id = ?",
                (STATE_READY, float(now), task_id),
            )
            self._store.audit(
                conn, "lease.released", task_id,
                {"token": int(token), "worker": row["worker"]},
            )
            # The mirror's release is INSIDE the transaction, so a
            # refusal by the mirror's own gate rolls this write back.
            self._mirror_release(task_id)
        return ReleasedRecord(
            task_id=task_id, token=int(token), worker=row["worker"]
        )

    # -- the reaper -------------------------------------------------------

    def reap(self, now: Optional[float] = None) -> tuple:
        """Sweep expired leases back into the queue.

        A crash is **not** the task's fault: the requeued task takes **no
        backoff delay** and does not consume the failure budget.  The
        checkpoints are untouched, so the next holder resumes from the
        newest one instead of redoing the work.

        Returns the leases that were swept.

        **A recorded refusal blocks the re-dispatch here too.**  This is
        the SECOND path that puts a task back to ``ready`` -- ``fail()``
        is the first -- and a gate that guards only ``fail()`` can be
        walked around: let the lease expire instead of reporting the
        failure, and the task is laundered back into the queue anyway.
        The crash path is the *cheaper* way around the guard, so it is
        the one a refusal has to close.

        A refused task is **skipped**, not raised: one refused task does
        not stop the other expired leases from being swept.  The refusal
        leaves the task leased, so its lease keeps expiring and the next
        sweep asks again -- and the refusal stays on the record.
        """
        now = self._clock() if now is None else float(now)
        swept = []
        for row in self._store.read(
            "SELECT * FROM ltc_task WHERE state = ? AND expires_at < ? "
            "ORDER BY task_id",
            (STATE_LEASED, float(now)),
        ):
            task_id = row["task_id"]
            with self._store.transaction() as conn:
                current = conn.execute(
                    "SELECT * FROM ltc_task WHERE task_id = ?", (task_id,)
                ).fetchone()
                if current is None or current["state"] != STATE_LEASED:
                    continue
                if float(current["expires_at"]) >= float(now):
                    continue
                if not self._refusal_allows_reap(task_id, str(current["task"]), now):
                    # Refused: the task keeps its state, its crash count
                    # and its lease.  The transaction ends without the
                    # UPDATE, so nothing is written.
                    continue
                # The mirror's release is INSIDE the transaction, and it
                # uses the BOOLEAN form: a refused mirror release must
                # skip this ONE task, not abandon the sweep.
                #
                # It is asked BEFORE the UPDATE, so a refusal leaves
                # the transaction without a write -- the task keeps its
                # lease and its crash count, and the mirror stays
                # ``reserved``, which is the state a leased task's
                # mirror job is in.
                if not self._mirror_release_allowed(task_id):
                    continue
                conn.execute(
                    "UPDATE ltc_task SET state = ?, worker = '', "
                    "delay_until = 0, crashes = crashes + 1 WHERE task_id = ?",
                    (STATE_READY, task_id),
                )
                self._store.audit(
                    conn, "lease.reaped", task_id,
                    {"worker": current["worker"], "token": int(current["token"]),
                     "crashes": int(current["crashes"]) + 1},
                )
            swept.append(
                ReapedLease(
                    task_id=task_id,
                    worker=row["worker"],
                    token=int(row["token"]),
                    expired_at=float(row["expires_at"]),
                    requeued_at=float(now),
                )
            )
        return tuple(swept)

    def expired_leases(self, now: Optional[float] = None) -> tuple:
        """The leases that :meth:`reap` would sweep, without sweeping them."""
        now = self._clock() if now is None else float(now)
        return tuple(
            ReapedLease(
                task_id=row["task_id"],
                worker=row["worker"],
                token=int(row["token"]),
                expired_at=float(row["expires_at"]),
                requeued_at=float(now),
            )
            for row in self._store.read(
                "SELECT * FROM ltc_task WHERE state = ? AND expires_at < ? "
                "ORDER BY task_id",
                (STATE_LEASED, float(now)),
            )
        )

    # -- the outbox hand-off ----------------------------------------------

    def outbox_messages(self, task_id: str) -> tuple:
        """The outbox rows of a task as ``outbox_pattern.OutboxMessage``s.

        The rows are the same objects the transactional outbox would hold;
        the message id is the stable idempotency key, so a replayed
        terminal state is the *same* message and cannot be delivered twice.
        """
        return tuple(
            OutboxMessage(
                message_id=row.message_id,
                destination=row.destination,
                payload=row.payload,
                seq=int(row.created_at),
            )
            for row in self.outbox_rows(task_id)
        )

    def mark_delivered(self, task_id: str, message_id: str,
                       now: Optional[float] = None) -> str:
        """Mark an outbox row as delivered (``sent``).

        The row stays in the ledger -- it is the idempotency record.
        """
        now = self._clock() if now is None else float(now)
        with self._store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM ltc_outbox WHERE message_id = ? AND task_id = ?",
                (message_id, task_id),
            ).fetchone()
            if row is None:
                raise UnknownTaskError(
                    f"no outbox row {message_id} for task {task_id}"
                )
            conn.execute(
                "UPDATE ltc_outbox SET state = ? WHERE message_id = ?",
                (MessageState.SENT.value, message_id),
            )
            self._store.audit(
                conn, "outbox.sent", task_id, {"message_id": message_id},
            )
        return MessageState.SENT.value

    def delivered(self, task_id: str) -> tuple:
        """The message ids of a task's outbox rows that were delivered."""
        return tuple(
            row.message_id
            for row in self.outbox_rows(task_id)
            if row.state == MessageState.SENT.value
        )

    # -- the hand-over -----------------------------------------------------

    def resume_from(self, task_id: str) -> Optional[CheckpointRecord]:
        """The checkpoint a new holder resumes from.

        This is the newest checkpoint of the task -- the step the new
        holder starts *after*.  It survives a reap: the reaper touches the
        lease, never the checkpoints.
        """
        return self.checkpoint(task_id)

    def pending_steps(self, task_id: str) -> int:
        """How many steps the task has checkpointed."""
        row = self._require_row(task_id)
        return int(row["last_step"])


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """The source's demonstration, driven end to end.

    worker-A claims (token 1) and checkpoints two steps, then dies.  The
    lease expires, the reaper sweeps it, worker-B claims (token 2) and
    resumes from A's checkpoint.  The woken zombie A is refused on every
    write.
    """
    manager = LeasedTaskClaim(max_failures=2, base_backoff_seconds=2.0)
    manager.enqueue_task("t1", "demo-task", payload="hello")

    lease_a = manager.claim("t1", "worker-A", ttl=10.0, now=100.0)
    assert lease_a.token == 1, lease_a
    manager.save_checkpoint("t1", lease_a.token, 1, {"step": "one"},
                            now=101.0)
    manager.save_checkpoint("t1", lease_a.token, 2, {"step": "two"},
                            now=102.0)

    # A crashes.  The lease expires; the reaper sweeps it with no backoff.
    swept = manager.reap(now=200.0)
    assert len(swept) == 1, swept
    view = manager.task("t1")
    assert view.state == STATE_READY and view.delay_until == 0.0, view
    assert view.failures == 0, view

    # B takes over: a new token, and the checkpoint survives.
    lease_b = manager.claim("t1", "worker-B", ttl=10.0, now=201.0)
    assert lease_b.token == 2, lease_b
    resumed = manager.resume_from("t1")
    assert resumed is not None and resumed.step == 2, resumed

    # The zombie writes: all three refused, nothing changed.
    for write in (
        lambda: manager.complete("t1", lease_a.token, now=202.0),
        lambda: manager.save_checkpoint("t1", lease_a.token, 3, {"x": 1},
                                        now=202.0),
        lambda: manager.heartbeat("t1", lease_a.token, now=202.0),
    ):
        try:
            write()
        except StaleLeaseError:
            pass
        else:  # pragma: no cover - the demo must fail loudly
            raise AssertionError("the zombie's write was accepted")
    assert manager.task("t1").state == STATE_LEASED

    # The live holder finishes; the terminal state and the outbox row
    # commit together, under the stable idempotency key.
    terminal = manager.complete("t1", lease_b.token, {"ok": True}, now=203.0)
    assert terminal.message_id == "t1:completed", terminal
    rows = manager.outbox_rows("t1")
    assert len(rows) == 1 and rows[0].message_id == "t1:completed", rows

    print(
        "leased-task-claim OK: monotonic token, zombie writes refused, "
        "reaper requeues without backoff, checkpoint survives the hand-over, "
        "terminal state commits with its outbox row"
    )


if __name__ == "__main__":
    main()
