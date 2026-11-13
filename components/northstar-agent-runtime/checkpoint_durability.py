"""Checkpoint durability modes: *when* a checkpoint reaches disk.

What was missing
----------------
Northstar has three checkpoint layers -- ``checkpoints.py`` (turn boundaries),
``checkpoint_store.py`` (atomic files) and ``durable_resume.py`` (the
append-only durable log) -- and none of them answers the question every
checkpoint system eventually has to answer: **is this checkpoint on disk yet?**

Every one of those layers writes *synchronously*.  A write is durable by the
time the call returns, so there is no window in which "the step ran" and "the
step is recorded" disagree.  That is safe, and it is also the slowest possible
policy: a long graph pays a disk round-trip at every super-step.

The alternative is to give up the guarantee and write in the background, so
the next step can start while the previous checkpoint is still in flight.  That
trades durability for latency, and -- this is the part that matters -- it
introduces a **loss window**: a process that dies in that window loses the
last checkpoint it thought it had.

LangGraph made this dimension explicit with its three **durability modes**,
selected per execution call rather than per graph:

* ``"exit"``   -- persist only when the run exits (success, error, or a
  human-in-the-loop interrupt).  Best performance on long graphs; nothing
  intermediate is saved, so a mid-run crash leaves nothing to resume from.
* ``"async"``  -- the default.  Persist asynchronously *while the next step
  executes*.  Good performance and good durability, but "there is a small risk
  that LangGraph does not write checkpoints if the process crashes during
  execution".
* ``"sync"``   -- persist throughout the run and await outstanding checkpointer
  promises before the run returns.  A crash mid-run can still lose recent
  checkpoints, but the run does not return until the pending writes have
  settled.

This module gives Northstar the same dimension, as a **write policy** over
the checkpoint store, and adds three things LangGraph does not have:

* a **receipt** for every write -- mode, checkpoint id, write timing and
  whether the write settled -- so a run's durability can be *audited* after
  the fact instead of assumed;
* an explicit **crash window** per mode, modelled and testable with an
  injected crash hook rather than a real ``kill -9``;
* a **cost grading** ("is losing one step expensive?") that turns the mode
  into a decision rather than a default.

Source
------
LangGraph official docs, "Checkpointers > Durability Modes",
https://docs.langchain.com/oss/javascript/langgraph/checkpointers -- the
three modes, their semantics, and the per-mode behaviour of the *first*
checkpoint of a new thread.

packetgeek, "LangGraph Checkpoints Part 2: Storage with SQLite",
https://www.packetgeek.net/2026/09/02/langgraph-checkpoints-part-2-storage-with-sqlite/
-- a 50-node graph measured once per mode on langgraph 1.2.11:
``exit`` wrote one checkpoint, ``async`` and ``sync`` each wrote fifty-two
("one per super-step plus the input"), and all three reached the same final
state.  The three modes differ in *when* the write happens, not in how many.

Northstar extensions (this module, not the source)
--------------------------------------------------
* the **receipt** format (mode / checkpoint id / timing / settled);
* the **integration point** with the rest of Northstar: the controller talks
  to a :class:`CheckpointSink`, and two adapters ship with it --
  :class:`FileSink` over ``checkpoint_store.FileCheckpointStorage`` and
  :class:`DurableStoreSink` over ``durable_resume.DurableStore``;
* the **crash-window model** and the **cost grading** (:class:`StepCost`);
* the fact that an *interrupted* run saves its checkpoint in every mode --
  the official docs imply the interrupt case only through the ``exit``
  bullet (persistence happens "successfully, with an error, or due to a
  human-in-the-loop interrupt"); the cross-mode guarantee is this slice's own
  reading, and Northstar makes it an awaited barrier rather than a race.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, Sequence

__all__ = [
    "CheckpointSink",
    "CrashWindow",
    "DurabilityController",
    "DurabilityError",
    "DurabilityInterrupt",
    "DurabilityMode",
    "DurabilityPolicy",
    "DurabilityReceipt",
    "DurabilityStateError",
    "DurableStoreSink",
    "FileSink",
    "InvalidDurabilityModeError",
    "MemorySink",
    "RunOutcome",
    "SimulatedCrash",
    "StepCost",
    "WriteTiming",
    "state_digest",
]


class DurabilityError(ValueError):
    """A durability mode or durability request the runtime refuses."""


class InvalidDurabilityModeError(DurabilityError):
    """A durability mode that is not one of the three known modes."""


class DurabilityStateError(DurabilityError):
    """A durability request made out of order (writing after the run ended)."""


class DurabilityMode(str, Enum):
    """The three durability modes, by LangGraph's names.

    ``EXIT`` persists only when the run exits.  ``ASYNC`` persists in the
    background while the next step runs.  ``SYNC`` persists and is awaited
    before the next step begins and before the run returns.
    """

    EXIT = "exit"
    ASYNC = "async"
    SYNC = "sync"

    @classmethod
    def parse(cls, value: Any) -> "DurabilityMode":
        """Parse a mode, refusing anything that is not exactly one of the three.

        Fail closed: an unknown mode is an error, never a silent default.
        A mode that is misspelled or capitalised differently is *not* the mode
        the caller meant, and guessing would pick a durability policy for
        them.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            for member in cls:
                if member.value == value:
                    return member
        raise InvalidDurabilityModeError(
            f"unknown durability mode {value!r}: expected one of "
            + ", ".join(repr(member.value) for member in cls)
        )


class WriteTiming(str, Enum):
    """When a checkpoint write happens, relative to the run."""

    #: Written once, when the run exits.
    ON_EXIT = "on_exit"
    #: Written in the background while the next step runs; the run never waits.
    BACKGROUND = "background"
    #: Written and awaited before the next step begins.
    AWAITED = "awaited"


class StepCost(str, Enum):
    """What it costs to lose one step.  (Northstar extension.)

    The source's selection guidance turns on this question -- use ``sync``
    "when you cannot afford to lose a step" (paying, sending mail) and
    ``exit`` for a batch job "that you would restart from the beginning
    anyway".  Northstar makes the question answerable: a step declares
    whether it can be recomputed or whether it has a side effect.
    """

    #: The step can be recomputed from its inputs; losing it costs time.
    RECOMPUTABLE = "recomputable"
    #: The step has a side effect; losing it costs the effect.
    SIDE_EFFECTING = "side_effecting"


@dataclass
class DurabilityReceipt:
    """What one checkpoint write did, and when.

    The four fields that matter are ``mode``, ``checkpoint_id``, ``timing``
    and ``settled``.  The rest is context.
    """

    #: The mode the run was under.
    mode: DurabilityMode
    #: The id of the checkpoint this write carries.
    checkpoint_id: str
    #: When the write happened relative to the run.
    timing: WriteTiming
    #: Whether the write has landed.  A background write starts ``False`` and
    #: flips to ``True`` when it lands.
    settled: bool = False
    #: Whether the run *waited* for this write.  A background write is never
    #: awaited, even once it has landed.
    awaited: bool = False
    #: The thread the run belongs to.
    thread_id: str = ""
    #: The index of the step the checkpoint was taken at (``-1`` = the input).
    step_index: int = -1
    #: ``"input"``, ``"start"``, ``"step"``, ``"interrupt"`` or ``"exit"``.
    kind: str = ""
    #: For an exit write: ``"completed"``, ``"error"`` or ``"interrupt"``.
    reason: str = ""
    #: The id the underlying store used, when it differs from ours.
    external_checkpoint_id: str | None = None
    #: The error that killed the write, if any.
    error: BaseException | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "checkpoint_id": self.checkpoint_id,
            "timing": self.timing.value,
            "settled": self.settled,
            "awaited": self.awaited,
            "thread_id": self.thread_id,
            "step_index": self.step_index,
            "kind": self.kind,
            "reason": self.reason,
            "external_checkpoint_id": self.external_checkpoint_id,
            "error": None if self.error is None else repr(self.error),
        }


@dataclass(frozen=True)
class CrashWindow:
    """What a crash costs under one mode.  (Northstar extension.)"""

    mode: DurabilityMode
    #: A crash loses *every* intermediate checkpoint.
    loses_all_progress: bool
    #: A crash may lose the last checkpoint that was taken.
    may_lose_last_checkpoint: bool
    #: Every step that had finished keeps its checkpoint.
    preserves_completed_steps: bool
    #: One line, for a receipt or a report.
    summary: str


@dataclass(frozen=True)
class DurabilityPolicy:
    """The write policy: what mode, and therefore when each write happens."""

    mode: DurabilityMode

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", DurabilityMode.parse(self.mode))

    @classmethod
    def parse(cls, mode: Any) -> "DurabilityPolicy":
        """Build a policy from a mode name or a :class:`DurabilityMode`."""
        return cls(mode=DurabilityMode.parse(mode))

    def write_timing(self, kind: str = "step") -> WriteTiming:
        """When a write of this kind happens under this mode."""
        if self.mode is DurabilityMode.EXIT:
            return WriteTiming.ON_EXIT
        if self.mode is DurabilityMode.SYNC:
            return WriteTiming.AWAITED
        return WriteTiming.BACKGROUND

    def awaits_writes(self) -> bool:
        """Whether the run waits for a write before the next step begins."""
        return self.mode is DurabilityMode.SYNC

    def crash_window(self) -> CrashWindow:
        """What a mid-run crash costs under this mode."""
        if self.mode is DurabilityMode.EXIT:
            return CrashWindow(
                mode=self.mode,
                loses_all_progress=True,
                may_lose_last_checkpoint=True,
                preserves_completed_steps=False,
                summary="a crash loses every intermediate checkpoint",
            )
        if self.mode is DurabilityMode.ASYNC:
            return CrashWindow(
                mode=self.mode,
                loses_all_progress=False,
                may_lose_last_checkpoint=True,
                preserves_completed_steps=False,
                summary="a crash may lose the last checkpoint, whose write was still in flight",
            )
        return CrashWindow(
            mode=self.mode,
            loses_all_progress=False,
            may_lose_last_checkpoint=False,
            preserves_completed_steps=True,
            summary="a crash loses at most the step that was in flight",
        )

    @staticmethod
    def recommend(cost: StepCost | None = None) -> DurabilityMode:
        """The mode to use for a step of this cost.

        ``SIDE_EFFECTING`` steps get ``SYNC`` -- losing the step costs the
        effect.  ``RECOMPUTABLE`` steps get ``EXIT`` -- losing the step costs
        a recomputation.  With no cost declared, the default is ``ASYNC``.
        """
        if cost is None:
            return DurabilityMode.ASYNC
        if isinstance(cost, str):
            cost = StepCost(cost)
        if cost is StepCost.SIDE_EFFECTING:
            return DurabilityMode.SYNC
        return DurabilityMode.EXIT


# ---------------------------------------------------------------------------
# Sinks: where a checkpoint write goes
# ---------------------------------------------------------------------------


class CheckpointSink(Protocol):
    """Where a checkpoint write goes.

    A sink is *durable* or not; the durability controller does not care which.
    It cares that the write is ordered, that a failure is reported rather
    than swallowed, and that the sink can say what it wrote.
    """

    def write(self, checkpoint_id: str, payload: Mapping[str, Any]) -> str:
        """Write ``payload`` under ``checkpoint_id``; return the stored id."""
        ...

    def exists(self, checkpoint_id: str) -> bool:
        """Whether a checkpoint with this id is present."""
        ...


class MemorySink:
    """A sink that keeps checkpoints in memory.  Used by tests and dry runs."""

    def __init__(self) -> None:
        self._payloads: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    def write(self, checkpoint_id: str, payload: Mapping[str, Any]) -> str:
        with self._lock:
            if checkpoint_id not in self._payloads:
                self._order.append(checkpoint_id)
            self._payloads[checkpoint_id] = dict(payload)
        return checkpoint_id

    def exists(self, checkpoint_id: str) -> bool:
        with self._lock:
            return checkpoint_id in self._payloads

    def load(self, checkpoint_id: str) -> dict[str, Any]:
        with self._lock:
            return dict(self._payloads[checkpoint_id])

    def ids(self) -> tuple[str, ...]:
        """Every stored id, in write order."""
        with self._lock:
            return tuple(self._order)

    def __len__(self) -> int:
        with self._lock:
            return len(self._payloads)


class FileSink:
    """A sink over ``checkpoint_store.FileCheckpointStorage``.

    The file layer already does the hard part -- atomic replace, fsync, path
    validation -- so the durability controller only has to decide *when* to
    call it.
    """

    def __init__(self, storage: Any) -> None:
        self._storage = storage

    def write(self, checkpoint_id: str, payload: Mapping[str, Any]) -> str:
        return self._storage.save(checkpoint_id, payload)

    def exists(self, checkpoint_id: str) -> bool:
        try:
            self._storage.load(checkpoint_id)
        except Exception:  # noqa: BLE001 - absent or unreadable both mean "not there"
            return False
        return True


class DurableStoreSink:
    """A sink over ``durable_resume.DurableStore``.

    The durable store allocates its own checkpoint ids (``ck-000001`` and up),
    so the sink maps Northstar's checkpoint id onto the store's and reports
    the store's id back through the receipt's ``external_checkpoint_id``.
    """

    def __init__(self, store: Any, *, run_id: str) -> None:
        self._store = store
        self._run_id = run_id
        self._by_ours: dict[str, str] = {}
        self._lock = threading.Lock()

    def write(self, checkpoint_id: str, payload: Mapping[str, Any]) -> str:
        state = payload.get("state") if isinstance(payload, Mapping) else None
        if not isinstance(state, Mapping):
            state = dict(payload) if isinstance(payload, Mapping) else {}
        with self._lock:
            existing = self._by_ours.get(checkpoint_id)
            if existing is not None:
                return existing
            checkpoint = self._store.put_checkpoint(
                run_id=self._run_id,
                state=dict(state),
                parent_checkpoint_id=payload.get("parent_checkpoint_id")
                if isinstance(payload, Mapping)
                else None,
                interrupted_task=payload.get("interrupted_task")
                if isinstance(payload, Mapping)
                else None,
                interrupt_value=payload.get("interrupt_value")
                if isinstance(payload, Mapping)
                else None,
                task_path=str(payload.get("task_path", "") or "")
                if isinstance(payload, Mapping)
                else "",
            )
            self._by_ours[checkpoint_id] = checkpoint.checkpoint_id
            return checkpoint.checkpoint_id

    def exists(self, checkpoint_id: str) -> bool:
        with self._lock:
            external = self._by_ours.get(checkpoint_id)
        if external is None:
            return False
        return self._store.get_checkpoint(self._run_id, external) is not None

    def external_id(self, checkpoint_id: str) -> str | None:
        with self._lock:
            return self._by_ours.get(checkpoint_id)


# ---------------------------------------------------------------------------
# The controller: the write policy, applied to a run
# ---------------------------------------------------------------------------


class SimulatedCrash(Exception):
    """A simulated process crash.  (Northstar extension.)

    Raised by the injected crash hook to stop a run the way a process death
    would, without killing the process.  The controller reacts to it exactly
    as it would react to a death: writes that were still in flight are lost.
    """


class DurabilityInterrupt(Exception):
    """A step asking for human input.

    The interrupt is a *pause*, not a failure: the checkpoint is saved in
    every mode, because the run has to leave something a resume can find.
    """

    def __init__(self, value: Any = None) -> None:
        super().__init__("the step asked for human input")
        self.value = value


@dataclass
class _BufferedWrite:
    """A write that has been issued but has not reached the sink yet."""

    receipt: DurabilityReceipt
    payload: dict[str, Any]
    #: The order this write was issued in.  Landing follows issue order, not
    #: schedule order.
    issue_seq: int = 0


class DurabilityController:
    """Applies a durability policy to one run.

    The controller is the only place that decides *when* a checkpoint write
    happens.  It is deliberately not a checkpoint *store*: it writes through a
    :class:`CheckpointSink`, so the same policy governs a file store, the
    durable log, or an in-memory sink.

    The write schedule, per mode:

    ``EXIT``
        Nothing is written while the run is going.  One write happens when
        the run exits -- successfully, with an error, or at an interrupt.

    ``ASYNC``
        Every checkpoint write is *scheduled* and lands while the next step
        executes.  The run never waits for a write, not even at the end: a
        write may still be in flight when the run returns.

    ``SYNC``
        Each step's checkpoint write is issued and awaited before the next
        step begins, so a completed step's checkpoint is always on disk.  The
        initial input and ``__start__`` writes are only *scheduled* (the
        source notes that admission visibility at that boundary matches
        ``async``); every outstanding write is awaited before the run
        returns.
    """

    def __init__(
        self,
        *,
        sink: CheckpointSink,
        mode: Any = DurabilityMode.ASYNC,
        thread_id: str = "thread-1",
        run_id: str | None = None,
        new_thread: bool = True,
        crash_hook: Callable[[str, int], None] | None = None,
        state_builder: Callable[[int], Mapping[str, Any]] | None = None,
        id_prefix: str = "ck",
        id_start: int = 1,
    ) -> None:
        self.sink = sink
        self.policy = DurabilityPolicy(mode=mode)
        self.mode = self.policy.mode
        self.thread_id = thread_id
        self.run_id = run_id or thread_id
        self.new_thread = new_thread
        self._crash_hook = crash_hook
        self._state_builder = state_builder
        self._id_prefix = id_prefix
        self._next_id = id_start
        self._receipts: list[DurabilityReceipt] = []
        self._buffer: list[_BufferedWrite] = []
        self._landed: list[str] = []
        self._started = False
        self._finished = False
        self._issue_seq = 0
        #: The checkpoint a resumed run continues from.
        self.resume_from: str | None = None

    # -- receipts --------------------------------------------------------

    @property
    def receipts(self) -> tuple[DurabilityReceipt, ...]:
        """Every write this run issued, in order."""
        return tuple(self._receipts)

    @property
    def landed_ids(self) -> tuple[str, ...]:
        """The checkpoint ids that actually reached the sink."""
        return tuple(self._landed)

    @property
    def outstanding(self) -> int:
        """How many issued writes have not reached the sink yet."""
        return len(self._buffer)

    def crash_window(self) -> CrashWindow:
        """What a crash costs under this run's mode."""
        return self.policy.crash_window()

    # -- helpers ---------------------------------------------------------

    def _new_checkpoint_id(self) -> str:
        checkpoint_id = f"{self._id_prefix}-{self._next_id:06d}"
        self._next_id += 1
        return checkpoint_id

    def _state_for(self, index: int) -> dict[str, Any]:
        if self._state_builder is None:
            return {"step": index}
        state = self._state_builder(index)
        if not isinstance(state, Mapping):
            raise DurabilityError("the state builder must return a mapping")
        return dict(state)

    def _payload(self, checkpoint_id: str, kind: str, index: int, state: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": "northstar.checkpoint-durability/1",
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "checkpoint_id": checkpoint_id,
            "mode": self.mode.value,
            "kind": kind,
            "step_index": index,
            "state": dict(state),
            "state_digest": state_digest(state),
        }

    def _crash_point(self, point: str, index: int) -> None:
        if self._crash_hook is None:
            return
        try:
            self._crash_hook(point, index)
        except SimulatedCrash:
            self._abort_pending()
            raise
        except Exception:
            # Any other failure out of the hook is treated as a crash too:
            # the run stops and the in-flight writes are lost, exactly as
            # they would be if the process had died.
            self._abort_pending()
            raise

    def _abort_pending(self) -> None:
        """Drop every write that had not reached the sink.  (A crash.)"""
        for buffered in self._buffer:
            buffered.receipt.settled = False
            buffered.receipt.error = SimulatedCrash("the write was in flight when the run died")
        self._buffer.clear()

    # -- writing ---------------------------------------------------------

    def _issue(
        self,
        *,
        kind: str,
        index: int,
        state: Mapping[str, Any],
        timing: WriteTiming,
        awaited: bool,
        reason: str = "",
        schedule_only: bool = False,
    ) -> DurabilityReceipt:
        """Issue one checkpoint write."""
        checkpoint_id = self._new_checkpoint_id()
        receipt = DurabilityReceipt(
            mode=self.mode,
            checkpoint_id=checkpoint_id,
            timing=timing,
            settled=False,
            awaited=awaited,
            thread_id=self.thread_id,
            step_index=index,
            kind=kind,
            reason=reason,
        )
        self._receipts.append(receipt)
        payload = self._payload(checkpoint_id, kind, index, state)
        if schedule_only:
            self._issue_seq += 1
            self._buffer.append(
                _BufferedWrite(receipt=receipt, payload=payload, issue_seq=self._issue_seq)
            )
            return receipt
        self._flush_one(receipt, payload)
        return receipt

    def _flush_one(self, receipt: DurabilityReceipt, payload: Mapping[str, Any]) -> None:
        """Hand one write to the sink and settle it."""
        try:
            external = self.sink.write(payload["checkpoint_id"], payload)
        except Exception as error:  # noqa: BLE001 - the failure is recorded, not swallowed
            receipt.settled = False
            receipt.error = error
            raise
        receipt.external_checkpoint_id = external
        receipt.settled = True
        self._landed.append(receipt.checkpoint_id)

    def _flush_buffer(self) -> None:
        """Land every scheduled write, in issue order.

        The writes are landed in the order they were *issued*, not the order
        they were scheduled, so a run that scheduled the input and step-0
        writes up front still lands those first.  That matters for ``SYNC``,
        where the source says the input and step ``0`` writes are scheduled
        during early ticks -- they must reach the store before the steps
        they precede.
        """
        pending = sorted(self._buffer, key=lambda item: item.issue_seq)
        self._buffer = []
        for buffered in pending:
            self._flush_one(buffered.receipt, buffered.payload)

    # -- the run ---------------------------------------------------------

    def start(self, state: Mapping[str, Any] | None = None) -> DurabilityReceipt | None:
        """The first checkpoint of a new thread.

        Per the source's per-mode description of a brand-new thread: the
        internal ``__start__`` superstep runs first and step ``0`` is the loop
        checkpoint written after it.

        * ``EXIT`` -- no checkpoint exists until the run ends, so nothing is
          written here.
        * ``ASYNC`` -- the input checkpoint write starts before the first user
          node executes and is *not* awaited.
        * ``SYNC`` -- the input and step ``0`` writes are scheduled during
          these early ticks and are not awaited either; the source notes
          that admission visibility at this boundary matches ``async``.
        """
        if self._started:
            raise DurabilityStateError("the run has already started")
        self._started = True
        if self.mode is DurabilityMode.EXIT:
            return None
        if not self.new_thread:
            return None
        payload_state = dict(state or {})
        if self.mode is DurabilityMode.SYNC:
            self._issue(
                kind="input",
                index=-1,
                state=payload_state,
                timing=WriteTiming.AWAITED,
                awaited=False,
                schedule_only=True,
            )
            self._issue(
                kind="start",
                index=0,
                state=payload_state,
                timing=WriteTiming.AWAITED,
                awaited=False,
                schedule_only=True,
            )
            return None
        self._issue(
            kind="input",
            index=-1,
            state=payload_state,
            timing=WriteTiming.BACKGROUND,
            awaited=False,
            schedule_only=True,
        )
        self._issue(
            kind="start",
            index=0,
            state=payload_state,
            timing=WriteTiming.BACKGROUND,
            awaited=False,
            schedule_only=True,
        )
        return None

    def step(self, index: int, state: Mapping[str, Any] | None = None) -> DurabilityReceipt | None:
        """The checkpoint taken after one super-step.

        ``EXIT`` writes nothing.  ``ASYNC`` schedules the write and returns
        without waiting -- the write lands *while the next step runs*.
        ``SYNC`` issues the write and waits for it to land, so it is on disk
        *before the next step starts*.
        """
        self._require_running()
        payload_state = self._state_for(index)
        if self.mode is DurabilityMode.EXIT:
            return None
        if self.mode is DurabilityMode.SYNC:
            receipt = self._issue(
                kind="step",
                index=index,
                state=payload_state,
                timing=WriteTiming.AWAITED,
                awaited=True,
            )
            return receipt
        return self._issue(
            kind="step",
            index=index,
            state=payload_state,
            timing=WriteTiming.BACKGROUND,
            awaited=False,
            schedule_only=True,
        )

    def interrupt(self, index: int, value: Any = None, state: Mapping[str, Any] | None = None) -> DurabilityReceipt:
        """The checkpoint taken when the run pauses for human input.

        In every mode the checkpoint is saved, because the run has to leave
        something a resume can find.  Northstar makes it an *awaited* barrier
        even under ``ASYNC``: the run is not going anywhere until the human
        answers, so there is no performance reason to leave the write in
        flight, and a resume that could not find the interrupt would be a
        worse failure than the one it is avoiding.
        """
        self._require_running()
        payload_state = dict(state or self._state_for(index))
        receipt = self._issue(
            kind="interrupt",
            index=index,
            state=payload_state,
            timing=WriteTiming.AWAITED,
            awaited=True,
            reason="interrupt",
        )
        return receipt

    def finish(self, *, reason: str = "completed", state: Mapping[str, Any] | None = None) -> DurabilityReceipt | None:
        """The run is over.

        * ``EXIT`` -- the single write happens here, whatever the reason.
        * ``ASYNC`` -- outstanding writes are *not* awaited; the run returns
          with writes possibly still in flight.
        * ``SYNC`` -- outstanding writes are awaited before returning.
        """
        self._require_running()
        self._finished = True
        if self.mode is DurabilityMode.EXIT:
            payload_state = dict(state or self._state_for(-1))
            return self._issue(
                kind="exit",
                index=-1,
                state=payload_state,
                timing=WriteTiming.ON_EXIT,
                awaited=True,
                reason=reason,
            )
        if self.mode is DurabilityMode.SYNC:
            self._flush_buffer()
        return None

    def await_pending(self) -> tuple[DurabilityReceipt, ...]:
        """Land every outstanding write and report the receipts that settled."""
        pending = list(self._buffer)
        self._flush_buffer()
        return tuple(buffered.receipt for buffered in pending)

    def resume(
        self,
        steps: Sequence[Callable[[], Any]],
        *,
        from_checkpoint_id: str,
        initial_state: Mapping[str, Any] | None = None,
        starting_index: int = 0,
    ) -> RunOutcome:
        """Resume a paused run from the checkpoint the interrupt left behind.

        The resumed run continues from the interrupt point: it does **not**
        write a new "input" checkpoint for a thread that already has one, and
        it does not re-run the steps that already finished.

        The resumed run's *own* step checkpoints follow the same mode rules.
        Under ``EXIT`` the resumed run writes one checkpoint when it exits;
        under ``ASYNC`` and ``SYNC`` it writes one per step it runs.
        """
        if not isinstance(from_checkpoint_id, str) or not from_checkpoint_id:
            raise DurabilityError("a resume must name the checkpoint it continues from")
        self.resume_from = from_checkpoint_id
        self._started = True
        self.new_thread = False
        return self._drive(
            steps,
            initial_state=initial_state,
            starting_index=starting_index,
        )

    # -- the crash hook ---------------------------------------------------

    def crash_at(self, point: str, index: int) -> None:
        """Fire the crash hook directly.

        The hook is normally called by the driver at its checkpoints; this is
        the same hook, exposed so a caller can crash the run at a named
        point.
        """
        self._crash_point(point, index)

    def _require_running(self) -> None:
        if not self._started:
            raise DurabilityStateError("the run has not started")
        if self._finished:
            raise DurabilityStateError("the run has already finished")

    # -- the driver -------------------------------------------------------

    def _drive(
        self,
        steps: Sequence[Callable[[], Any]],
        *,
        initial_state: Mapping[str, Any] | None = None,
        starting_index: int = 0,
    ) -> RunOutcome:
        """The shared step loop behind :meth:`run` and :meth:`resume`."""
        last_state = dict(initial_state or {})
        for offset, step in enumerate(steps):
            index = starting_index + offset
            # The input and step-0 writes were scheduled during the early
            # ticks of the run; they land before the first user node runs,
            # which is what makes the thread visible to a reader.
            if offset == 0:
                self._flush_buffer()
            self._crash_point("before_step", index)
            try:
                value = step()
            except DurabilityInterrupt as paused:
                # A pause is not a failure: the checkpoint is saved in every
                # mode, and so are the writes that were still in flight.
                self._flush_buffer()
                receipt = self.interrupt(index, paused.value, state=last_state)
                return RunOutcome(
                    mode=self.mode,
                    status="interrupted",
                    final_state=last_state,
                    receipts=self.receipts,
                    landed=self.landed_ids,
                    interrupt_checkpoint_id=receipt.checkpoint_id,
                    interrupt_value=paused.value,
                )
            except Exception as error:  # noqa: BLE001 - the run ends with the error
                self._finished = True
                if self.mode is DurabilityMode.EXIT:
                    self._issue(
                        kind="exit",
                        index=index,
                        state=last_state,
                        timing=WriteTiming.ON_EXIT,
                        awaited=True,
                        reason="error",
                    )
                elif self.mode is DurabilityMode.SYNC:
                    self._flush_buffer()
                return RunOutcome(
                    mode=self.mode,
                    status="error",
                    final_state=last_state,
                    receipts=self.receipts,
                    landed=self.landed_ids,
                    error=error,
                )
            if isinstance(value, Mapping):
                last_state = dict(value)
            # Under ``ASYNC`` the writes scheduled before this step land
            # *while this step runs*: the background writer drains here, so a
            # write issued at the end of the previous step is on disk by the
            # time this step's body returns.  The write for this step is
            # issued afterwards and stays in flight.
            if self.mode is DurabilityMode.ASYNC:
                self._flush_buffer()
            self.step(index, last_state)
            self._crash_point("after_step", index)
        self._crash_point("before_exit", len(steps) - 1)
        self.finish(reason="completed", state=last_state)
        # How many writes were still in flight when the run's work was done.
        # ``SYNC`` and ``EXIT`` have awaited every write by now; ``ASYNC``
        # has not, and that is the whole difference between the two.
        outstanding_at_return = self.outstanding
        outcome = RunOutcome(
            mode=self.mode,
            status="completed",
            final_state=last_state,
            receipts=self.receipts,
            landed=self.landed_ids,
            outstanding_at_return=outstanding_at_return,
        )
        # The background writer drains after the run has returned: the run
        # never *waited* for those writes, but they do land.  This is what the
        # measured source saw -- fifty-two rows in the store after the run.
        self._flush_buffer()
        outcome.landed = self.landed_ids
        outcome.receipts = self.receipts
        return outcome

    def run(
        self,
        steps: Sequence[Callable[[], Any]],
        *,
        initial_state: Mapping[str, Any] | None = None,
    ) -> RunOutcome:
        """Drive ``steps`` under this run's durability policy.

        ``steps`` is a list of zero-argument callables.  Each one is one
        super-step.  A step that raises :class:`DurabilityInterrupt` pauses
        the run; a step that raises anything else ends it with an error.

        The crash hook fires at four named points: ``"before_input"``,
        ``"before_step"``, ``"after_step"`` and ``"before_exit"``.  The
        hook's ``index`` is the step it fires at (``-1`` for the input).
        """
        self.start(initial_state)
        self._crash_point("before_input", -1)
        return self._drive(steps, initial_state=initial_state)


@dataclass
class RunOutcome:
    """What a run did, and what reached the sink."""

    mode: DurabilityMode
    status: str
    final_state: dict[str, Any] = field(default_factory=dict)
    receipts: tuple[DurabilityReceipt, ...] = ()
    landed: tuple[str, ...] = ()
    error: BaseException | None = None
    interrupt_checkpoint_id: str | None = None
    interrupt_value: Any = None
    #: How many writes were still in flight when the run's work was done.
    #: ``ASYNC`` leaves writes outstanding; ``EXIT`` and ``SYNC`` do not.
    outstanding_at_return: int = 0

    @property
    def checkpoint_count(self) -> int:
        """How many checkpoints reached the sink."""
        return len(self.landed)

    def receipt_for(self, checkpoint_id: str) -> DurabilityReceipt | None:
        for receipt in self.receipts:
            if receipt.checkpoint_id == checkpoint_id:
                return receipt
        return None


def state_digest(state: Mapping[str, Any]) -> str:
    """A canonical digest of a checkpoint state.

    Same shape as ``durable_resume.state_digest``: canonical JSON, sorted
    keys, compact separators, UTF-8, SHA-256.
    """
    import hashlib
    import json

    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
