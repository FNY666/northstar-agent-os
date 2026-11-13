"""Durable checkpoints, retry-clears-writes, and an explicit resume command.

What was missing
----------------
Northstar had a sealed ledger and a turn-boundary checkpoint, but no story for a
run that dies *in the middle of a step*.  Three gaps, all of them the same gap
seen from different sides:

1. **A checkpoint recorded where the run got to, but not what was in flight.**
   ``checkpoints.Checkpoint`` holds a transcript length, a digest of that prefix
   and the consumed counters.  There was nowhere for a *pending* write -- a side
   effect the step declared but had not committed -- to live.  So a killed run's
   in-flight work was either invisible or, worse, indistinguishable from work
   that had actually landed.

2. **Nothing cleared pending writes before a retry.**  A retried step re-ran its
   body, so a write it declared on the first attempt was declared again on the
   second.  With no record of which declaration had been committed, "the effect
   happened once" was a hope, not a fact.

3. **Resume was a re-sent prompt.**  ``sessions.SessionStore.resume_transcript``
   rebuilds the transcript and the shutdown unwind pass synthesises an
   ``interrupted`` result for every ``tool_use`` that never got one.  That is
   the right *shape* of a resume -- a killed turn is explicitly not a success --
   but it is a transcript-level replay: there was no command a caller could hand
   back to say "resume *this* step with *this* value".

This module supplies the three missing pieces, in one place, so they cannot
drift apart:

* **State and pending writes are two ordered records.**  A checkpoint holds the
  committed state; the writes a step declared are appended to the durable log
  under that checkpoint, in the order they were declared, and are committed (or
  dropped) explicitly.  The store is append-only, so "dropped" is a tombstone
  record, never a rewrite.
* **A retry clears the pending writes first, then re-runs the step.**  The
  clear is what makes the effect happen once: the applier is only ever called
  for a write that is *newly* committed, and a retried attempt's declarations
  were never committed.
* **A resume is an explicit command.**  ``Command(resume=...)`` re-enters the
  interrupted step *from its start*, matching resume values to the step's
  interrupts in order.  Re-sending the prompt is not a resume and is refused.

Two rules this module does not bend
------------------------------------
* **No run id, no checkpoint.**  A checkpoint with no ``run_id`` cannot be
  stored, read back, or resumed from -- the store refuses it, because a
  checkpoint that cannot be named cannot be told apart from another one.
* **An interrupted step's writes are never replayed as successes.**  The
  shutdown unwind pass synthesises an ``interrupted`` result for a call that
  never ran; those calls are dropped as *uncommitted* on resume, exactly like
  the pending writes of a killed step.

Honest scope: this is the *shape* of LangGraph's four mechanisms -- a
``BaseCheckpointSaver`` that keeps state and pending writes apart, a
``RetryPolicy`` with a ``retry_on`` predicate, ``run_with_retry``'s
``task.writes.clear()``, and ``interrupt()``/``Command(resume=...)`` -- not a
port of LangGraph.  The mapping is written out in
``docs/design/durable-resume.md``.

Version pin: ``durable-resume.v1``
Schema pin: ``northstar.durable-resume.v1``
"""

from __future__ import annotations

import hashlib
import json
import os
import random as random_module
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

#: Module version pin.
DURABLE_RESUME_VERSION = "durable-resume.v1"

#: Schema pin carried by every record this module writes.
SCHEMA_PIN = "northstar.durable-resume.v1"

#: The two record kinds the durable log holds.
RECORD_CHECKPOINT = "checkpoint"
RECORD_PENDING_WRITES = "pending_writes"
RECORD_CLEARED_WRITES = "cleared_writes"
RECORD_COMMITTED_WRITES = "committed_writes"


# ---------------------------------------------------------------------------
# Errors: every one of them is a refusal, and every refusal is loud
# ---------------------------------------------------------------------------


class DurableResumeError(Exception):
    """Base class for every refusal this module makes."""


class MissingRunIdError(DurableResumeError):
    """A checkpoint was requested without a run (thread) id.

    LangGraph's ``BaseCheckpointSaver`` says it in one sentence: without a
    ``thread_id`` the checkpointer "cannot save state, resume from interrupts,
    or enable time-travel debugging".  Same rule here -- the id is the primary
    key, and a checkpoint that cannot be named cannot be told apart.
    """


class CheckpointIntegrityError(DurableResumeError):
    """A checkpoint's state does not hash to the digest it recorded."""


class InterruptRequiresCheckpointError(DurableResumeError):
    """A step asked to interrupt with no checkpointer to resume from.

    An interrupt without a durable checkpoint is a pause nobody can leave, so
    it is refused at the moment it happens rather than silently swallowed.
    """


class ResumeRequiresCommandError(DurableResumeError):
    """Something other than an explicit ``Command`` was offered as a resume."""


class ResumeValueMismatchError(DurableResumeError):
    """A resume value does not belong to the interrupt it was offered for."""


class RetryExhaustedError(DurableResumeError):
    """Every attempt of a step failed and the policy gave up.

    Raised instead of returning the last failure, so an exhausted retry can
    never be mistaken for a step that succeeded.
    """


class DurableStoreError(DurableResumeError):
    """The durable log is malformed or cannot be read back."""


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------


def _canonical(value: Any) -> bytes:
    """Deterministic bytes for a value, so a digest describes one history."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")


def state_digest(state: Mapping[str, Any]) -> str:
    """The digest a checkpoint records for its state."""
    return "sha256:" + hashlib.sha256(_canonical(dict(state))).hexdigest()


def _require_run_id(run_id: Any) -> str:
    if not isinstance(run_id, str) or not run_id.strip():
        raise MissingRunIdError(
            "a checkpoint needs a run id: without one it cannot be stored, read back, or resumed from"
        )
    return run_id


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DurableStoreError(f"{name} must be a non-empty string")
    return value


# ---------------------------------------------------------------------------
# The records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PendingWrite:
    """One write a step declared: a side effect it *intends* to land.

    A pending write is not a fact about the world.  It becomes one only when it
    is committed, and the store's commit step is the only place an effect is
    applied -- which is what makes "the effect happened once" a fact rather
    than a hope.
    """

    #: The step that declared the write.
    task_id: str
    #: The declaration's position in the step, zero-based. Writes are ordered
    #: by ``(task_path, task_id, idx)`` -- the order live execution applies
    #: them in.
    idx: int
    #: What the write is about (a channel name, in the state's own words).
    channel: str
    #: The write's payload.
    value: Any = None
    #: A stable key for the *effect* this write causes.  Two writes with the
    #: same key are the same effect; the store commits it once.
    effect_key: str | None = None
    #: The path of the task that declared the write.
    task_path: str = ""

    def __post_init__(self) -> None:
        _require_text(self.task_id, "task_id")
        _require_text(self.channel, "channel")
        if isinstance(self.idx, bool) or not isinstance(self.idx, int) or self.idx < 0:
            raise DurableStoreError("idx must be a non-negative int")

    @property
    def sort_key(self) -> tuple[str, str, int]:
        """The order writes are applied in."""
        return (self.task_path, self.task_id, self.idx)

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "idx": self.idx,
            "channel": self.channel,
            "value": self.value,
            "effect_key": self.effect_key,
            "task_path": self.task_path,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PendingWrite":
        return cls(
            task_id=str(value["task_id"]),
            idx=int(value["idx"]),
            channel=str(value["channel"]),
            value=value.get("value"),
            effect_key=value.get("effect_key"),
            task_path=str(value.get("task_path", "") or ""),
        )


@dataclass(frozen=True)
class DurableCheckpoint:
    """A durable boundary: the committed state, and where to resume from.

    The state is the *committed* state only.  The writes a step had in flight
    are not in here -- they hang off the checkpoint as their own ordered
    records, and they are committed or dropped on their own terms.
    """

    run_id: str
    checkpoint_id: str
    seq: int
    state: dict[str, Any] = field(default_factory=dict)
    state_digest: str = ""
    parent_checkpoint_id: str | None = None
    #: The step that was interrupted at this boundary, if any.
    interrupted_task: str | None = None
    #: The value the interrupted step asked for.
    interrupt_value: Any = None
    task_path: str = ""
    #: The resume answers already given to this task, keyed by interrupt id.
    #: A re-executed step re-reads them, so a second interrupt in the same
    #: step does not ask the question again.
    interrupt_answers: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_run_id(self.run_id)
        _require_text(self.checkpoint_id, "checkpoint_id")
        if not self.state_digest:
            object.__setattr__(self, "state_digest", state_digest(self.state))
        if state_digest(self.state) != self.state_digest:
            raise CheckpointIntegrityError(
                f"checkpoint {self.checkpoint_id!r} does not hash to its own digest"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "run_id": self.run_id,
            "checkpoint_id": self.checkpoint_id,
            "seq": self.seq,
            "state": self.state,
            "state_digest": self.state_digest,
            "parent_checkpoint_id": self.parent_checkpoint_id,
            "interrupted_task": self.interrupted_task,
            "interrupt_value": self.interrupt_value,
            "task_path": self.task_path,
            "interrupt_answers": dict(self.interrupt_answers),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DurableCheckpoint":
        if value.get("schema") != SCHEMA_PIN:
            raise DurableStoreError("a durable checkpoint record has an unknown schema")
        answers = value.get("interrupt_answers") or {}
        if not isinstance(answers, Mapping):
            raise DurableStoreError("interrupt_answers must be a mapping")
        return cls(
            run_id=str(value["run_id"]),
            checkpoint_id=str(value["checkpoint_id"]),
            seq=int(value["seq"]),
            state=dict(value.get("state") or {}),
            state_digest=str(value.get("state_digest") or ""),
            parent_checkpoint_id=value.get("parent_checkpoint_id"),
            interrupted_task=value.get("interrupted_task"),
            interrupt_value=value.get("interrupt_value"),
            task_path=str(value.get("task_path", "") or ""),
            interrupt_answers=dict(answers),
        )


@dataclass(frozen=True)
class Command:
    """An explicit instruction to resume.

    ``resume`` is the value the interrupted step receives.  It may be a single
    value (which resumes the step's *next* interrupt), a sequence of values
    (matched to the step's interrupts in order), or a mapping of interrupt id
    to value.

    A prompt is not a command.  ``runner.resume`` refuses anything that is not
    a :class:`Command`, because re-sending the prompt is what this module
    exists to stop being called a resume.
    """

    resume: Any = None
    #: Reserved for the graph a command is addressed to; the single-graph
    #: runtime here has exactly one.
    graph: str | None = None
    #: A state update to apply before the step re-enters.
    update: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Interrupt:
    """A step's request to be paused, with the value it asked for."""

    value: Any
    task_id: str
    index: int

    @property
    def interrupt_id(self) -> str:
        """The stable id a resume value may be addressed to."""
        return f"{self.task_id}#{self.index}"

    def as_dict(self) -> dict[str, Any]:
        return {"value": self.value, "task_id": self.task_id, "index": self.index}


class GraphInterrupt(Exception):
    """Raised inside a step to pause it.

    LangGraph's ``GraphInterrupt``; the same rule applies -- the first
    ``interrupt()`` call in a step raises, and only an explicit
    ``Command(resume=...)`` lets the step continue.
    """

    def __init__(self, interrupts: Sequence[Interrupt]) -> None:
        self.interrupts = tuple(interrupts)
        super().__init__(
            "the step was interrupted: " + ", ".join(item.interrupt_id for item in self.interrupts)
        )


# ---------------------------------------------------------------------------
# The store: state and pending writes are two ordered records
# ---------------------------------------------------------------------------


class DurableStore:
    """The append-only durable log of checkpoints and pending writes.

    Two record kinds, kept apart on purpose:

    * a **checkpoint** holds the committed state of a run at a boundary;
    * a **pending-writes** record holds, under one checkpoint, the writes a
      step declared, in the order it declared them.

    A write becomes real only when a **committed-writes** record lands; a
    write that is dropped lands as a **cleared-writes** record.  Both are
    appends -- the log is never rewritten, so "the write was dropped" and
    "the write never happened" are distinguishable after the fact.

    The store is the ``BaseCheckpointSaver`` of this module: ``put`` (here
    :meth:`put_checkpoint`), ``put_writes`` (here :meth:`put_writes`),
    ``get_tuple`` (here :meth:`get_checkpoint`), ``list`` (here
    :meth:`list_checkpoints`) and ``delete_thread`` (here
    :meth:`delete_thread`).
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._checkpoints: list[DurableCheckpoint] = []
        self._pending: dict[str, list[PendingWrite]] = {}
        self._cleared: dict[str, list[PendingWrite]] = {}
        self._committed: dict[str, list[PendingWrite]] = {}
        self._committed_effects: set[str] = set()

    # -- writing ----------------------------------------------------------

    def put_checkpoint(
        self,
        *,
        run_id: str,
        state: Mapping[str, Any],
        parent_checkpoint_id: str | None = None,
        interrupted_task: str | None = None,
        interrupt_value: Any = None,
        task_path: str = "",
    ) -> DurableCheckpoint:
        """Store the committed state of a run at a boundary.

        A run id is mandatory: without one the record cannot be found again,
        and a checkpoint nobody can find is not a checkpoint.
        """
        _require_run_id(run_id)
        if not isinstance(state, Mapping):
            raise DurableStoreError("state must be a mapping")
        seq = len(self._checkpoints) + 1
        checkpoint = DurableCheckpoint(
            run_id=run_id,
            checkpoint_id=f"ck-{seq:06d}",
            seq=seq,
            state=dict(state),
            state_digest=state_digest(state),
            parent_checkpoint_id=parent_checkpoint_id,
            interrupted_task=interrupted_task,
            interrupt_value=interrupt_value,
            task_path=task_path,
        )
        self._checkpoints.append(checkpoint)
        self._append({"kind": RECORD_CHECKPOINT, **checkpoint.as_dict()})
        return checkpoint

    def put_writes(self, checkpoint_id: str, writes: Sequence[PendingWrite]) -> tuple[PendingWrite, ...]:
        """Hang a step's pending writes under a checkpoint, in order.

        The order is the order live execution applies them in: by
        ``(task_path, task_id, idx)``.  A write is *pending* -- declared, not
        committed -- so nothing has happened yet.
        """
        if checkpoint_id not in self._checkpoint_ids():
            raise DurableStoreError(f"no checkpoint {checkpoint_id!r} to hang writes under")
        ordered = sorted(writes, key=lambda write: write.sort_key)
        bucket = self._pending.setdefault(checkpoint_id, [])
        bucket.extend(ordered)
        self._append(
            {
                "kind": RECORD_PENDING_WRITES,
                "checkpoint_id": checkpoint_id,
                "writes": [write.as_dict() for write in ordered],
            }
        )
        return tuple(ordered)

    def clear_writes(
        self,
        checkpoint_id: str,
        *,
        reason: str,
        effect_keys: frozenset[str] | None = None,
        task_id: str | None = None,
    ) -> tuple[PendingWrite, ...]:
        """Drop a step's uncommitted writes.

        This is the ``task.writes.clear()`` of LangGraph's ``run_with_retry``:
        before a retry (or a resume re-entry) the writes the previous attempt
        declared are dropped, so a re-run cannot apply the same effect twice.

        ``effect_keys`` narrows the drop to particular effects -- which is how
        the shutdown unwind pass's interrupted calls are discarded without
        discarding the writes that did land.  ``task_id`` narrows it to one
        task's declarations.
        """
        bucket = self._pending.get(checkpoint_id, [])

        def keep(write: PendingWrite) -> bool:
            if task_id is not None and write.task_id != task_id:
                return True
            if effect_keys is not None and (write.effect_key or "") not in effect_keys:
                return True
            return False

        dropped = [write for write in bucket if not keep(write)]
        self._pending[checkpoint_id] = [write for write in bucket if keep(write)]
        if dropped:
            self._cleared.setdefault(checkpoint_id, []).extend(dropped)
            self._append(
                {
                    "kind": RECORD_CLEARED_WRITES,
                    "checkpoint_id": checkpoint_id,
                    "reason": reason,
                    "writes": [write.as_dict() for write in dropped],
                }
            )
        return tuple(dropped)

    def commit_writes(
        self,
        checkpoint_id: str,
        *,
        applier: Callable[[PendingWrite], Any] | None = None,
    ) -> tuple[PendingWrite, ...]:
        """Apply and commit the pending writes under a checkpoint.

        A write whose ``effect_key`` was already committed is *not* applied
        again: the effect happened once, and this is where that is enforced
        rather than hoped for.
        """
        bucket = list(self._pending.get(checkpoint_id, []))
        applied: list[PendingWrite] = []
        for write in bucket:
            key = write.effect_key
            if key is not None and key in self._committed_effects:
                continue
            if applier is not None:
                applier(write)
            applied.append(write)
            if key is not None:
                self._committed_effects.add(key)
        self._pending[checkpoint_id] = []
        if applied:
            self._committed.setdefault(checkpoint_id, []).extend(applied)
            self._append(
                {
                    "kind": RECORD_COMMITTED_WRITES,
                    "checkpoint_id": checkpoint_id,
                    "writes": [write.as_dict() for write in applied],
                }
            )
        return tuple(applied)

    def delete_thread(self, run_id: str) -> None:
        """Forget every checkpoint and write of a run."""
        _require_run_id(run_id)
        keep = [item for item in self._checkpoints if item.run_id != run_id]
        dropped = {item.checkpoint_id for item in self._checkpoints} - {
            item.checkpoint_id for item in keep
        }
        self._checkpoints = keep
        for mapping in (self._pending, self._cleared, self._committed):
            for key in dropped:
                mapping.pop(key, None)
        self._append({"kind": "delete_thread", "run_id": run_id})

    # -- reading ----------------------------------------------------------

    def _checkpoint_ids(self) -> set[str]:
        return {item.checkpoint_id for item in self._checkpoints}

    def get_checkpoint(self, run_id: str, checkpoint_id: str) -> DurableCheckpoint | None:
        """One checkpoint of a run, or ``None``."""
        _require_run_id(run_id)
        for item in self._checkpoints:
            if item.run_id == run_id and item.checkpoint_id == checkpoint_id:
                return item
        return None

    def latest_checkpoint(self, run_id: str) -> DurableCheckpoint | None:
        """The newest checkpoint of a run."""
        _require_run_id(run_id)
        found = [item for item in self._checkpoints if item.run_id == run_id]
        return found[-1] if found else None

    def list_checkpoints(self, run_id: str) -> tuple[DurableCheckpoint, ...]:
        """Every checkpoint of a run, oldest first."""
        _require_run_id(run_id)
        return tuple(item for item in self._checkpoints if item.run_id == run_id)

    def pending_writes(self, checkpoint_id: str) -> tuple[PendingWrite, ...]:
        """The writes still pending under a checkpoint, in order."""
        return tuple(sorted(self._pending.get(checkpoint_id, []), key=lambda write: write.sort_key))

    def cleared_writes(self, checkpoint_id: str) -> tuple[PendingWrite, ...]:
        """The writes that were dropped under a checkpoint."""
        return tuple(self._cleared.get(checkpoint_id, []))

    def committed_writes(self, checkpoint_id: str) -> tuple[PendingWrite, ...]:
        """The writes that were committed under a checkpoint, in order."""
        return tuple(sorted(self._committed.get(checkpoint_id, []), key=lambda write: write.sort_key))

    def verify(self, checkpoint: DurableCheckpoint) -> bool:
        """Whether a checkpoint still hashes to its own digest.

        A checkpoint whose state was edited under it is refused, never
        continued: the resume would inherit counters describing a different
        history.
        """
        return state_digest(checkpoint.state) == checkpoint.state_digest

    # -- durability -------------------------------------------------------

    def _append(self, record: Mapping[str, Any]) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


# ---------------------------------------------------------------------------
# Retry: the policy, and the rule that a retry clears the writes first
# ---------------------------------------------------------------------------

#: The default ``retry_on`` predicate's name, for the report and the docs.
DEFAULT_RETRY_ON = "default_retry_on"

#: Statuses a server may answer with that mean "come back later".
THROTTLE_STATUSES: frozenset[int] = frozenset({429, 503})

#: Statuses that mean "the server failed", not "you did something wrong".
SERVER_ERROR_STATUSES: frozenset[int] = frozenset({500, 502, 504, 507, 508})


def _status_of(error: BaseException) -> int | None:
    """The HTTP status an error carries, if it carries one."""
    for name in ("status_code", "status", "http_status"):
        value = getattr(error, name, None)
        if isinstance(value, int) and not isinstance(value, bool) and 100 <= value < 600:
            return value
    response = getattr(error, "response", None)
    value = getattr(response, "status_code", None)
    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value < 600:
        return value
    return None


def default_retry_on(error: BaseException) -> bool:
    """Which failures may be retried.

    The rule, in the runtime's own vocabulary:

    * **throttling** (429, 503) and **server errors** (5xx) are retried --
      they are the peer's load, not our mistake;
    * **authentication and permission failures** (401, 403, 407) are *not*
      retried -- a retry cannot fix a credential, and repeating the request
      would repeat the refusal;
    * a **connection** failure (the connection was never established, so no
      request byte reached the peer) is retried;
    * a **post-write** failure (the connection dropped after the request was
      written) is *not* retried -- the peer may already have executed it.

    The last two rules are ``retry_contract``'s, not invented here: a
    post-write drop is ``FailureClass.NON_RETRYABLE`` with
    ``may_have_executed=True`` there, and this predicate agrees with it.  The
    classification is delegated rather than re-derived, so the two modules
    cannot drift.

    Anything this predicate cannot place is **not** retried.  "We could not
    tell" is not "transient", and treating it as transient turns every bug
    into a request storm against the thing that is already failing.
    """
    from retry_contract import classify_exception

    status = _status_of(error)
    if status is not None:
        if status in THROTTLE_STATUSES or status in SERVER_ERROR_STATUSES:
            return True
        if status in (401, 403, 407):
            return False
        if 400 <= status < 500:
            return False
        return False
    failure = classify_exception(error)
    if failure.classification is not None and getattr(failure.classification, "value", "") == "retryable":
        return True
    return False


@dataclass(frozen=True)
class RetryPolicy:
    """How a failing step is retried.

    The five fields are LangGraph's ``RetryPolicy`` fields, with the same
    meaning: ``initial_interval`` (seconds before the first retry),
    ``backoff_factor`` (the multiplier), ``max_interval`` (the ceiling),
    ``max_attempts`` (the total number of attempts, *including* the first),
    and ``jitter`` (whether the wait is randomized).

    ``retry_on`` is a *predicate*: it takes the exception and answers whether
    the step may be tried again.  A class, a sequence of classes, and a
    callable are all accepted; the callable is the shape this module uses,
    because "is this failure transient" is a question about the failure, not
    about its type.
    """

    initial_interval: float = 0.5
    backoff_factor: float = 2.0
    max_interval: float = 128.0
    max_attempts: int = 3
    jitter: bool = True
    retry_on: Callable[[BaseException], bool] = default_retry_on

    def __post_init__(self) -> None:
        if self.initial_interval < 0:
            raise DurableStoreError("initial_interval must be >= 0")
        if self.backoff_factor < 1.0:
            raise DurableStoreError("backoff_factor must be >= 1.0")
        if self.max_interval < self.initial_interval:
            raise DurableStoreError("max_interval must be >= initial_interval")
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) or self.max_attempts < 1:
            raise DurableStoreError("max_attempts must be >= 1")
        if not callable(self.retry_on):
            raise DurableStoreError("retry_on must be callable")

    def should_retry(self, error: BaseException) -> bool:
        """Whether this failure may be retried under this policy."""
        return bool(self.retry_on(error))

    def delay(self, attempt: int, random: Callable[[], float] | None = None) -> float:
        """The wait before retry number ``attempt`` (1 = the first retry).

        The schedule is a pure function of the attempt number, so a run's
        waits can be replayed from the record without a clock.
        """
        if attempt < 1:
            raise DurableStoreError("attempt must be >= 1")
        interval = self.initial_interval * (self.backoff_factor ** (attempt - 1))
        interval = min(interval, self.max_interval)
        if not self.jitter:
            return interval
        draw = random() if random is not None else random_module.random()
        return interval + draw

    def as_dict(self) -> dict[str, Any]:
        return {
            "initial_interval": self.initial_interval,
            "backoff_factor": self.backoff_factor,
            "max_interval": self.max_interval,
            "max_attempts": self.max_attempts,
            "jitter": self.jitter,
        }


@dataclass(frozen=True)
class Attempt:
    """One attempt of a step."""

    #: 1-indexed, the way LangGraph's ``node_attempt`` counts.
    index: int
    error: BaseException | None = None
    cleared: tuple[PendingWrite, ...] = ()

    @property
    def failed(self) -> bool:
        return self.error is not None


@dataclass(frozen=True)
class StepResult:
    """What a step produced."""

    value: Any = None
    attempts: tuple[Attempt, ...] = ()
    committed: tuple[PendingWrite, ...] = ()
    cleared: tuple[PendingWrite, ...] = ()

    @property
    def attempt_count(self) -> int:
        return len(self.attempts)

    @property
    def succeeded(self) -> bool:
        return bool(self.attempts) and self.attempts[-1].error is None


# ---------------------------------------------------------------------------
# The runner: interrupt, resume, retry
# ---------------------------------------------------------------------------


class DurableRunner:
    """Runs steps against a :class:`DurableStore`.

    Three behaviours, one place:

    * **Interrupt.**  A step calls ``runner.interrupt(value)``.  The first
      call in a step raises :class:`GraphInterrupt`; the runner stores the
      interrupt under a checkpoint and stops.  Without a store there is
      nothing to resume from, so the interrupt is refused outright.
    * **Resume.**  ``runner.resume(command)`` re-enters the interrupted step
      *from its start*, handing it the command's ``resume`` value.  The
      step's logic before the interrupt runs again -- that is the rule, not an
      accident -- so the writes it declared before the interrupt are dropped
      first, and only the ones the re-run declares are committed.
    * **Retry.**  A step that fails with a retryable failure is retried
      under the policy.  Before each retry the step's pending writes are
      cleared, so the effect happens once.

    The runner refuses a resume that is not a :class:`Command`.  A re-sent
    prompt is not a resume: it would restart the run from the top with no
    record of what had already committed.
    """

    def __init__(
        self,
        *,
        store: DurableStore | None = None,
        policy: RetryPolicy | None = None,
        sleep: Callable[[float], None] | None = None,
        random: Callable[[], float] | None = None,
    ) -> None:
        self.store = store
        self.policy = policy or RetryPolicy()
        self._sleep = sleep if sleep is not None else time.sleep
        self._random = random
        self._interrupts: list[Interrupt] = []
        self._answers: dict[str, Any] = {}
        self._task_id: str = ""
        self._checkpoint_id: str | None = None
        self._applier: Callable[[PendingWrite], Any] | None = None
        self._pending: list[PendingWrite] = []

    # -- interrupt --------------------------------------------------------

    def interrupt(self, value: Any) -> Any:
        """Pause the step and ask for a value.

        The first call raises :class:`GraphInterrupt`; the runner has
        already recorded the interrupt against the current checkpoint.
        """
        if self.store is None:
            raise InterruptRequiresCheckpointError(
                "a step may not interrupt without a checkpointer: without one the pause "
                "cannot be left and the work would be lost"
            )
        index = len(self._interrupts)
        record = Interrupt(value=value, task_id=self._task_id, index=index)
        self._interrupts.append(record)
        if record.interrupt_id in self._answers:
            return self._answers[record.interrupt_id]
        raise GraphInterrupt((record,))
    # -- pending writes ---------------------------------------------------

    def declare(self, write: PendingWrite) -> PendingWrite:
        """Declare a write the step intends to make.

        The write is *pending*: nothing has happened yet.  It is applied only
        when the step succeeds and its writes are committed.
        """
        if not isinstance(write, PendingWrite):
            raise DurableStoreError("declare takes a PendingWrite")
        self._pending.append(write)
        if self.store is not None and self._checkpoint_id is not None:
            self.store.put_writes(self._checkpoint_id, [write])
        return write

    def _clear_pending(self, reason: str) -> tuple[PendingWrite, ...]:
        """Drop the writes the current attempt declared."""
        dropped = tuple(self._pending)
        self._pending = []
        if self.store is not None and self._checkpoint_id is not None:
            self.store.clear_writes(self._checkpoint_id, reason=reason)
        return dropped

    # -- running ----------------------------------------------------------

    def run(
        self,
        *,
        task_id: str,
        step: Callable[[], Any],
        state: Mapping[str, Any] | None = None,
        run_id: str | None = None,
        applier: Callable[[PendingWrite], Any] | None = None,
        checkpoint_id: str | None = None,
    ) -> StepResult:
        """Run one step, with the retry rule applied.

        The step is called with no arguments and returns its value.  Writes
        are declared with :meth:`declare` from inside the step.
        """
        self._task_id = task_id
        self._pending = []
        self._applier = applier
        if self.store is not None:
            if checkpoint_id is None:
                checkpoint_id = self.store.put_checkpoint(
                    run_id=run_id or task_id,
                    state=dict(state or {}),
                    task_path=task_id,
                ).checkpoint_id
            self._checkpoint_id = checkpoint_id
        attempts: list[Attempt] = []
        attempt_index = 0
        while True:
            attempt_index += 1
            try:
                value = step()
            except GraphInterrupt as paused:
                self._record_interrupt(paused, state=state, run_id=run_id)
                raise
            except Exception as error:  # noqa: BLE001 - classification decides
                cleared = self._clear_pending(f"attempt {attempt_index} failed")
                attempts.append(Attempt(index=attempt_index, error=error, cleared=cleared))
                if attempt_index >= self.policy.max_attempts:
                    raise RetryExhaustedError(
                        f"the step {task_id!r} failed after {attempt_index} attempt(s): "
                        f"{type(error).__name__}: {error}"
                    ) from error
                if not self.policy.should_retry(error):
                    raise
                self._sleep(self.policy.delay(attempt_index, self._random))
                continue
            committed = ()
            if self.store is not None and self._checkpoint_id is not None:
                committed = self.store.commit_writes(
                    self._checkpoint_id, applier=self._applier
                )
            attempts.append(Attempt(index=attempt_index, cleared=tuple(self._pending)))
            return StepResult(
                value=value,
                attempts=tuple(attempts),
                committed=committed,
                cleared=(),
            )

    def resume(
        self,
        command: Command,
        *,
        task_id: str,
        step: Callable[[], Any],
        state: Mapping[str, Any] | None = None,
        run_id: str | None = None,
        applier: Callable[[PendingWrite], Any] | None = None,
        checkpoint_id: str | None = None,
    ) -> StepResult:
        """Re-enter an interrupted step with an explicit command.

        The step restarts from its beginning: the logic before the interrupt
        runs again, exactly as LangGraph's does.  What differs is that the
        writes the interrupted attempt declared are dropped first, so the
        re-run's declarations are the only ones that can commit.
        """
        if not isinstance(command, Command):
            raise ResumeRequiresCommandError(
                "a resume must be an explicit Command(resume=...): re-sending the prompt "
                "restarts the run and loses the record of what had already committed"
            )
        if self.store is None:
            raise InterruptRequiresCheckpointError(
                "a resume needs a checkpointer: without one there is no boundary to re-enter"
            )
        target = checkpoint_id
        if target is None:
            latest = self.store.latest_checkpoint(run_id or task_id)
            if latest is None:
                raise DurableStoreError("there is no checkpoint to resume from")
            target = latest.checkpoint_id
        checkpoint = self.store.get_checkpoint(run_id or task_id, target)
        if checkpoint is None:
            raise DurableStoreError(f"no checkpoint {target!r} to resume from")
        if not self.store.verify(checkpoint):
            raise CheckpointIntegrityError(
                f"checkpoint {checkpoint.checkpoint_id!r} does not match its digest: the "
                "history it describes is not the history in the store"
            )
        answer = self._match_answer(command.resume, checkpoint)
        self._answers = dict(checkpoint.interrupt_answers)
        self._answers.update(answer)
        # The interrupted attempt's writes are dropped: they never landed.
        self.store.clear_writes(checkpoint.checkpoint_id, reason="the step was resumed")
        # The step restarts, so its interrupt counter starts over: the first
        # interrupt of the re-run is the first interrupt again.
        self._interrupts = []
        return self.run(
            task_id=task_id,
            step=step,
            state=state,
            run_id=run_id or task_id,
            applier=applier,
            checkpoint_id=checkpoint.checkpoint_id,
        )

    def _record_interrupt(
        self,
        paused: GraphInterrupt,
        *,
        state: Mapping[str, Any] | None,
        run_id: str | None,
    ) -> DurableCheckpoint:
        """Store the interrupt against a checkpoint so a resume can find it.

        The checkpoint records *which* task was interrupted and *what* it
        asked for, so the resume command's value can be matched to it.
        """
        if self.store is None:  # pragma: no cover - interrupt() already refused
            raise InterruptRequiresCheckpointError("an interrupt needs a checkpointer")
        record = paused.interrupts[0] if paused.interrupts else Interrupt(value=None, task_id=self._task_id, index=0)
        answers = dict(self._answers)
        checkpoint = DurableCheckpoint(
            run_id=run_id or self._task_id,
            checkpoint_id=self._checkpoint_id or f"ck-int-{len(self.store.list_checkpoints(run_id or self._task_id)) + 1:06d}",
            seq=len(self.store.list_checkpoints(run_id or self._task_id)) + 1,
            state=dict(state or {}),
            parent_checkpoint_id=self._checkpoint_id,
            interrupted_task=record.task_id,
            interrupt_value=record.value,
            task_path=self._task_id,
            interrupt_answers=answers,
        )
        self.store._checkpoints.append(checkpoint)
        self.store._append({"kind": RECORD_CHECKPOINT, **checkpoint.as_dict()})
        self._checkpoint_id = checkpoint.checkpoint_id
        return checkpoint

    def _match_answer(self, resume: Any, checkpoint: DurableCheckpoint) -> dict[str, Any]:
        """Match a resume value to the interrupt it belongs to.

        A mapping is matched by interrupt id.  A sequence is matched to the
        step's interrupts *in order* -- the first value answers the first
        interrupt.  A single value answers the step's next unanswered
        interrupt.  A value that belongs to no interrupt of this task is
        refused: resume values are scoped to the task that asked.
        """
        task = checkpoint.interrupted_task or self._task_id
        answered = set(checkpoint.interrupt_answers)
        if isinstance(resume, Mapping):
            if not resume:
                raise ResumeValueMismatchError("the resume command carries no value")
            matched: dict[str, Any] = {}
            for key, value in resume.items():
                interrupt_id = str(key)
                if not interrupt_id.startswith(f"{task}#"):
                    raise ResumeValueMismatchError(
                        f"resume value {interrupt_id!r} does not belong to task {task!r}"
                    )
                matched[interrupt_id] = value
            return matched
        if isinstance(resume, (list, tuple)):
            if not resume:
                raise ResumeValueMismatchError("the resume command carries no value")
            return {f"{task}#{index}": value for index, value in enumerate(resume)}
        # A single value answers the step's next unanswered interrupt.
        index = 0
        while f"{task}#{index}" in answered:
            index += 1
        return {f"{task}#{index}": resume}


# ---------------------------------------------------------------------------
# The seam with sessions.py: unwound calls are uncommitted, never successes
# ---------------------------------------------------------------------------


def unwind_effect_keys(transcript: Sequence[Any]) -> frozenset[str]:
    """The effect keys of the calls the shutdown unwind pass says never ran.

    ``sessions.SessionStore.resume_transcript`` synthesises an explicitly
    ``interrupted`` result for every ``tool_use`` that never got one.  Those
    calls did not run, so their writes are *uncommitted*: they are dropped on
    a resume, and they are never replayed as successes.  This function maps
    that verdict onto the effect keys the durable store uses.
    """
    from shutdown_unwind import pending_tool_uses

    return frozenset(f"tool:{call_id}" for call_id, _name in pending_tool_uses(transcript))


def drop_unwound_writes(
    store: DurableStore,
    checkpoint_id: str,
    transcript: Sequence[Any],
) -> tuple[PendingWrite, ...]:
    """Drop the pending writes of the calls the unwind pass says never ran.

    This is the join between the two halves of the runtime's story: the
    session layer knows which calls were interrupted, and the durable layer
    knows which writes are still pending.  A write whose effect belongs to an
    interrupted call is dropped -- it never landed, and a resume must not
    pretend it did.
    """
    keys = unwind_effect_keys(transcript)
    if not keys:
        return ()
    return store.clear_writes(
        checkpoint_id,
        reason="the call was interrupted and never ran",
        effect_keys=keys,
    )


def committed_writes_only(store: DurableStore, checkpoint_id: str) -> tuple[PendingWrite, ...]:
    """The writes that actually landed, in order.

    A resume replays these and nothing else.  Pending and cleared writes are
    excluded by construction: a cleared write was dropped, and a pending one
    has not happened.
    """
    return store.committed_writes(checkpoint_id)


# ---------------------------------------------------------------------------
# The seam with long_horizon.py: only verified progress may reach a checkpoint
# ---------------------------------------------------------------------------


def checkpoint_from_verified(
    *,
    run_id: str,
    round_index: int,
    objective: str,
    verified_progress: Sequence[Any],
    context_digest: str,
) -> dict[str, Any]:
    """The state a long-horizon round's checkpoint holds.

    The state is built from the auditor-verified progress only.  There is no
    parameter for the executor's summary, so an executor's claim cannot reach
    a durable checkpoint even by accident -- the same structural argument
    ``long_horizon`` makes about the Manager's rebuild.
    """
    if not verified_progress:
        raise DurableStoreError("a checkpoint needs at least one verified progress entry")
    for item in verified_progress:
        if getattr(item, "summary", None) is None:
            raise DurableStoreError("a verified progress entry must carry a summary")
    return {
        "round_index": round_index,
        "objective": objective,
        "verified_progress": [item.as_dict() for item in verified_progress],
        "context_digest": context_digest,
    }


def verify_verified_checkpoint(
    store: DurableStore,
    checkpoint: DurableCheckpoint,
    *,
    expected_round_index: int,
) -> bool:
    """Whether a durable checkpoint still carries the verified progress it claimed.

    A checkpoint whose state was edited under it is refused: a resume would
    otherwise inherit counters describing a different history.
    """
    if not store.verify(checkpoint):
        return False
    state = checkpoint.state
    if int(state.get("round_index", -1)) != expected_round_index:
        return False
    return bool(state.get("verified_progress"))
