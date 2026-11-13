"""A versioned resume marker and hook-based retry, split from run state.

Northstar's ledger mixes two questions: *where did the run stop* and *what
state was the run in*.  A lineage checkpoint (``checkpoints.py``) answers the
first with a full record - transcript digest, budget counters, permission
mode, lineage ids - and therefore carries state along with position.  A run
that was cancelled can still be resumed from such a record, because the
record says where to continue and nothing in it says the run was revoked.

This module takes the split that Strands Agents (AWS's open-source agent
SDK) makes, and keeps only the parts that answer the kill-switch question:

* **The marker carries position, never state.**  A :class:`Checkpoint` here is
  a frozen dataclass with exactly three fields: ``position`` (which boundary
  fired), ``cycle_index``, and ``schema_version``.  It holds no conversation,
  no counters, no credentials.  Cross-process state continuity is a
  *different* concern, owned by a session manager - not this marker.
* **The precedence is explicit.**  :func:`resolve_outcome` settles three
  claims on the same run in one order: ``interrupt > checkpoint > cancel``.
  A cancelled run that also has a checkpoint comes back as **cancelled**;
  it never comes back quietly as a checkpoint.
* **Retry is a hook, not loop code.**  A :class:`ModelRetryStrategy`
  registers callbacks on the model-call and invocation events; the loop only
  *emits* events and never asks whether to retry.  The strategy decides.

Verbatim from Strands Agents (harness SDK, commit ``4330e22``, read from the
brief - the upstream repository was not cloned during this slice):

* ``strands-py/src/strands/experimental/checkpoint/checkpoint.py:46`` -
  ``Checkpoint`` is a frozen dataclass whose fields are ``position``
  (``"after_model" | "after_tools"``), ``cycle_index`` and
  ``schema_version``; ``from_dict()`` raises ``CheckpointException`` when
  ``schema_version`` does not match.
* The module docstring of that file: "It captures the position (which
  boundary fired) and the cycle index. It does not capture conversation state
  - pair with a SessionManager for cross-process state continuity."
* ``strands-py/src/strands/event_loop/_retry.py:21`` -
  ``ModelRetryStrategy`` is a ``HookProvider`` that registers callbacks for
  ``AfterModelCallEvent`` / ``AfterInvocationEvent``; it retries only
  throttling errors by default (``is_retryable()`` may be overridden by a
  subclass), the backoff is exponential 4s, 8s, 16s, 32s, 64s with a 240s
  ceiling, ``max_attempts`` is 6, and the state resets after a success.

Northstar extensions (ours, not Strands'):

* The precedence is *callable* - :func:`resolve_outcome` returns the winning
  claim - and it treats a cancel as the kill switch: it wins over a
  checkpoint.  Strands states the order in a comment; here it is enforced.
* The event names are Northstar's own (``after_model`` / ``after_tools`` /
  ``after_invocation``), not Strands' ``AfterModelCallEvent``.
* The retry strategy here decides *whether* to retry and how long to wait;
  it never sleeps.  The wait is handed back to the caller as a number, so a
  test can assert the sequence without waiting for it.
* A ``falsy`` interrupt answer (``False``, ``0``, ``""``) counts as an
  answer.  The falsy-answer failure mode is taken from an AG-UI report
  (PR #2451, 2026-08) as a *test-case inspiration only* - AG-UI's code was
  not read, so it is not presented as a verified upstream behaviour.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

#: Schema version of the marker written by this module.
CHECKPOINT_SCHEMA_VERSION = 1

#: The boundaries a marker may name.
POSITION_AFTER_MODEL = "after_model"
POSITION_AFTER_TOOLS = "after_tools"
POSITIONS: tuple[str, ...] = (POSITION_AFTER_MODEL, POSITION_AFTER_TOOLS)

#: The outcomes :func:`resolve_outcome` can return.
OUTCOME_INTERRUPT = "interrupt"
OUTCOME_CHECKPOINT = "checkpoint"
OUTCOME_CANCELLED = "cancelled"
OUTCOME_NONE = "none"

#: The precedence, highest first.  A cancel outranks a checkpoint.
OUTCOME_PRECEDENCE: tuple[str, ...] = (
    OUTCOME_INTERRUPT,
    OUTCOME_CHECKPOINT,
    OUTCOME_CANCELLED,
)


class CheckpointException(Exception):
    """A marker that cannot be read as a marker.

    Raised for a ``schema_version`` that this module does not know, for a
    position that is not a boundary, and for a payload that carries
    anything other than the three marker fields.
    """


class CheckpointError(CheckpointException):
    """Alias kept for readers who expect the ``*Error`` spelling."""


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CheckpointException(f"{name} must be an integer")
    return value


@dataclass(frozen=True)
class Checkpoint:
    """A resume marker: the boundary that fired, and the cycle it fired in.

    The marker holds **no run state**.  There is no field for a transcript,
    for a counter, or for a credential, and :meth:`from_dict` refuses a
    payload that carries one - the separation is enforced, not documented.

    ``position`` is the boundary that fired (``"after_model"`` or
    ``"after_tools"``); ``cycle_index`` is the agent loop's cycle number at
    that boundary.  ``schema_version`` pins the shape of the payload.
    """

    position: str
    cycle_index: int
    schema_version: int = CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.position not in POSITIONS:
            raise CheckpointException(
                f"position must be one of {POSITIONS!r}, got {self.position!r}"
            )
        _require_int(self.cycle_index, "cycle_index")
        _require_int(self.schema_version, "schema_version")
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION:
            raise CheckpointException(
                f"unknown checkpoint schema_version {self.schema_version!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        """The wire form: exactly the three marker fields."""
        return {
            "position": self.position,
            "cycle_index": self.cycle_index,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "Checkpoint":
        """Read a marker.  Refuses a version it does not know, and state.

        Two refusals, both fail-closed:

        * ``schema_version`` that is not this module's version raises
          :class:`CheckpointException` - a marker from a future or a
          different scheme is not read as one of ours;
        * a payload with any field outside the three marker fields is
          refused.  A dict that carries conversation state is not a marker,
          and this is where that is enforced.
        """
        if not isinstance(value, Mapping):
            raise CheckpointException("a checkpoint marker must be a mapping")
        data = dict(value)
        version = data.get("schema_version")
        if version != CHECKPOINT_SCHEMA_VERSION:
            raise CheckpointException(
                f"unknown checkpoint schema_version {version!r}"
            )
        unknown = sorted(set(data) - {"position", "cycle_index", "schema_version"})
        if unknown:
            raise CheckpointException(
                "a checkpoint marker carries position, cycle_index and "
                f"schema_version only; unexpected field(s): {', '.join(unknown)}"
            )
        if "position" not in data:
            raise CheckpointException("a checkpoint marker must carry a position")
        if "cycle_index" not in data:
            raise CheckpointException("a checkpoint marker must carry a cycle_index")
        return cls(
            position=data["position"],
            cycle_index=data["cycle_index"],
            schema_version=version,
        )


#: The sentinel that means "there is no interrupt".  ``None`` is the only
#: value that means "no answer yet" - a falsy *answer* is an answer.
NO_INTERRUPT = object()


@dataclass(frozen=True)
class Cancel:
    """A cancellation claim, and whether it is already in force.

    ``applied`` distinguishes two things that are both called "a cancel":

    * ``applied=False`` - the cancellation has been *requested* but has not
      been carried out.  It is a claim competing with a checkpoint.
    * ``applied=True`` - the run was *revoked*.  This is the kill switch.

    A plain value passed as ``cancel`` (a reason string, ``True``, a
    tombstone) is read as an **applied** cancel: a cancellation is never
    assumed to be merely pending, because the cost of that assumption is a
    revoked run quietly resuming.
    """

    reason: str = ""
    applied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "applied": self.applied}


def cancel_is_in_force(cancel: Any) -> bool:
    """True when the cancellation has been carried out, not just requested."""
    if cancel is None:
        return False
    if isinstance(cancel, Cancel):
        return bool(cancel.applied)
    return True


def has_answer(interrupt: Any) -> bool:
    """True when ``interrupt`` is an answer, even a falsy one.

    ``False``, ``0`` and ``""`` are answers.  Only the sentinel
    :data:`NO_INTERRUPT` and ``None`` mean "nothing was answered".

    This is the failure mode the AG-UI report (PR #2451, 2026-08) names:
    a falsy answer read as "not answered".  AG-UI's code was not read for
    this slice, so this is the *test-case inspiration*, implemented here as
    Northstar's own rule.
    """
    if interrupt is NO_INTERRUPT or interrupt is None:
        return False
    return True


def resolve_outcome(
    *,
    interrupt: Any = NO_INTERRUPT,
    checkpoint: Any = None,
    cancel: Any = None,
) -> str:
    """Settle the three claims on a run: interrupt, checkpoint, cancel.

    The precedence, highest first, is::

        interrupt > checkpoint > cancel

    and one rule overrides it: a cancellation that is **already in force**
    is the kill switch, and a revoked run comes back as ``"cancelled"`` -
    never quietly as ``"checkpoint"``.  So the resolution is:

    1. an **interrupt** (any answer, falsy answers included) wins outright;
    2. a cancel **in force** wins over a checkpoint;
    3. a **checkpoint** wins over a cancel that is merely *requested*;
    4. otherwise the outcome is ``"none"``.

    Why the override rather than a flat order: the source states the order
    for claims competing at one moment.  In Northstar a cancel is also a
    *fact about the run* - it was revoked - and a revoked run must not be
    resumed by a marker.  Rule 3 therefore needs a cancel that is
    explicitly *pending* (:class:`Cancel` with ``applied=False``); any
    other cancel value is read as applied.  The distinction is Northstar's
    extension, not Strands'.
    """
    if has_answer(interrupt):
        return OUTCOME_INTERRUPT
    if cancel_is_in_force(cancel):
        return OUTCOME_CANCELLED
    if checkpoint is not None:
        return OUTCOME_CHECKPOINT
    if cancel is not None:
        return OUTCOME_CANCELLED
    return OUTCOME_NONE


def resume_outcome(
    *,
    checkpoint: Any = None,
    cancel: Any = None,
    interrupt: Any = NO_INTERRUPT,
) -> str:
    """The outcome for a run that is *coming back* from a marker.

    Same rules as :func:`resolve_outcome`, read for the resume path: a run
    that was revoked returns ``"cancelled"`` and the marker is not used; a
    run that was not revoked returns ``"checkpoint"``.
    """
    return resolve_outcome(interrupt=interrupt, checkpoint=checkpoint, cancel=cancel)


# -- retry as a hook -----------------------------------------------------

#: The events the runtime emits around a model call.  Northstar's own names;
#: Strands' equivalents are ``AfterModelCallEvent`` / ``AfterInvocationEvent``.
EVENT_AFTER_MODEL = "after_model"
EVENT_AFTER_TOOLS = "after_tools"
EVENT_AFTER_INVOCATION = "after_invocation"

#: The events a retry strategy subscribes to.
RETRY_EVENTS: tuple[str, ...] = (EVENT_AFTER_MODEL, EVENT_AFTER_INVOCATION)

#: The default backoff, in seconds: 4, 8, 16, 32, 64 - Strands' values.
DEFAULT_BACKOFF_SECONDS: tuple[float, ...] = (4.0, 8.0, 16.0, 32.0, 64.0)

#: The ceiling on a single wait: 240 seconds.
DEFAULT_MAX_BACKOFF_SECONDS = 240.0

#: The default number of attempts, retries included.
DEFAULT_MAX_ATTEMPTS = 6


class ThrottledError(Exception):
    """A retryable failure: the provider asked us to slow down."""


class RetryDecision:
    """What the hook decided about one failed model call."""

    def __init__(
        self,
        *,
        retry: bool,
        attempt: int,
        wait_seconds: float = 0.0,
        error: BaseException | None = None,
        reason: str = "",
    ) -> None:
        self.retry = bool(retry)
        self.attempt = int(attempt)
        self.wait_seconds = float(wait_seconds)
        self.error = error
        self.reason = reason

    def as_dict(self) -> dict[str, Any]:
        return {
            "retry": self.retry,
            "attempt": self.attempt,
            "wait_seconds": self.wait_seconds,
            "reason": self.reason,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"RetryDecision(retry={self.retry!r}, attempt={self.attempt!r}, "
            f"wait_seconds={self.wait_seconds!r}, reason={self.reason!r})"
        )


class ModelRetryStrategy:
    """Retry as a hook provider: the loop emits, the strategy decides.

    The strategy registers callbacks for the model-call events; the agent
    loop never asks it whether to retry and never calls a retry function.
    The loop's only job is to emit ``after_model`` / ``after_invocation``;
    what happens next is the strategy's business.

    Defaults (Strands' values, copied verbatim):

    * only **throttling** failures are retried - :meth:`is_retryable`
      returns true for :class:`ThrottledError` and false for anything else;
      a subclass may override it;
    * the backoff is exponential, 4s, 8s, 16s, 32s, 64s, capped at 240s;
    * ``max_attempts`` is 6 (the first try plus five retries);
    * a success resets the attempt counter and the backoff.

    The strategy never sleeps.  It returns the number of seconds the caller
    should wait, so the schedule can be asserted without waiting for it.
    """

    def __init__(
        self,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_seconds: Sequence[float] = DEFAULT_BACKOFF_SECONDS,
        max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS,
    ) -> None:
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int):
            raise ValueError("max_attempts must be an integer")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if not backoff_seconds:
            raise ValueError("backoff_seconds must not be empty")
        self.max_attempts = max_attempts
        self.backoff_seconds = tuple(float(value) for value in backoff_seconds)
        self.max_backoff_seconds = float(max_backoff_seconds)
        self._attempts = 0
        self._callbacks: dict[str, list[Any]] = {event: [] for event in RETRY_EVENTS}

    # -- hook registration ------------------------------------------------
    def register_callback(self, event: str, callback: Any) -> None:
        """Register a callback for one of the model-call events."""
        if event not in self._callbacks:
            raise ValueError(
                f"unknown event {event!r}; expected one of {sorted(self._callbacks)}"
            )
        if not callable(callback):
            raise ValueError("a retry callback must be callable")
        self._callbacks[event].append(callback)

    def callbacks_for(self, event: str) -> tuple[Any, ...]:
        """The callbacks registered for one event."""
        return tuple(self._callbacks.get(event, ()))

    def register(self) -> None:
        """Register the strategy's own hook on the events it subscribes to.

        The runtime's hook provider contract is "a provider registers its
        callbacks"; this method is the provider side of it.  The registry
        itself lives in ``hooks.py`` and is not touched by this slice.
        """
        for event in RETRY_EVENTS:
            self.register_callback(event, self.after_model_call)

    # -- the hook itself --------------------------------------------------
    def after_model_call(self, event: Mapping[str, Any] | None = None) -> RetryDecision:
        """The hook body: decide whether the failed call is retried.

        ``event`` is the emitted event mapping.  The error is read from
        ``event["error"]`` (an exception) and the success flag from
        ``event["error"] is None``.
        """
        payload = dict(event or {})
        error = payload.get("error")
        if error is None:
            self.reset()
            return RetryDecision(
                retry=False,
                attempt=self._attempts,
                reason="the call succeeded",
            )
        if not self.is_retryable(error):
            return RetryDecision(
                retry=False,
                attempt=self._attempts,
                error=error,
                reason=f"{type(error).__name__} is not retryable",
            )
        self._attempts += 1
        if self._attempts >= self.max_attempts:
            return RetryDecision(
                retry=False,
                attempt=self._attempts,
                wait_seconds=self.backoff_for(self._attempts),
                error=error,
                reason=(
                    f"max_attempts ({self.max_attempts}) reached; "
                    f"{type(error).__name__} is not retried again"
                ),
            )
        return RetryDecision(
            retry=True,
            attempt=self._attempts,
            wait_seconds=self.backoff_for(self._attempts),
            error=error,
            reason=f"{type(error).__name__} is retryable",
        )

    # -- policy -----------------------------------------------------------
    def is_retryable(self, error: BaseException) -> bool:
        """Only throttling failures are retried.  Override in a subclass."""
        return isinstance(error, ThrottledError)

    def backoff_for(self, attempt: int) -> float:
        """The wait before the given attempt's retry, in seconds.

        The first retry waits 4s, the second 8s, and so on, capped at
        ``max_backoff_seconds``.  An attempt beyond the backoff table waits
        the ceiling.
        """
        if attempt < 1:
            return 0.0
        index = min(attempt - 1, len(self.backoff_seconds) - 1)
        wait = self.backoff_seconds[index]
        return min(wait, self.max_backoff_seconds)

    def reset(self) -> None:
        """Forget the attempt history - called after a success."""
        self._attempts = 0

    @property
    def attempts(self) -> int:
        """How many retries have been taken since the last success."""
        return self._attempts


class ModelCallLoop:
    """A model-call loop that only emits events.

    The point of this class is what it does **not** contain: there is no
    ``retry(...)`` call, no backoff arithmetic and no error classification.
    The loop calls the provider, and on failure it *emits* the
    ``after_model`` event and lets the registered hooks decide what
    happens.  A hook that says "retry" is honoured by the caller of
    :meth:`call`; the loop itself has no opinion.

    This is Northstar's own shape, built for this slice to make the
    separation testable.  It is not wired into ``loop.py`` (read-only for
    this slice), and it does not claim to be the runtime's agent loop.
    """

    def __init__(self, *, provider: Any = None) -> None:
        if provider is not None and not callable(provider):
            raise ValueError("provider must be callable")
        self._provider = provider
        self._handlers: dict[str, list[Any]] = {
            event: [] for event in (EVENT_AFTER_MODEL, EVENT_AFTER_TOOLS, EVENT_AFTER_INVOCATION)
        }
        self.emitted: list[dict[str, Any]] = []
        self.calls = 0

    def on(self, event: str, handler: Any) -> None:
        """Register a handler for one event."""
        if event not in self._handlers:
            raise ValueError(f"unknown event {event!r}")
        if not callable(handler):
            raise ValueError("a handler must be callable")
        self._handlers[event].append(handler)

    def emit(self, event: str, payload: Mapping[str, Any] | None = None) -> list[Any]:
        """Emit an event and return what the handlers said."""
        body = dict(payload or {})
        self.emitted.append({"event": event, **body})
        results: list[Any] = []
        for handler in self._handlers.get(event, ()):
            results.append(handler(body))
        return results

    def call(self, prompt: str) -> Any:
        """Call the provider; on failure emit ``after_model`` and return the
        hooks' answers.  The loop does not decide whether to retry."""
        self.calls += 1
        if self._provider is None:
            raise RuntimeError("this loop has no provider")
        try:
            result = self._provider(prompt)
        except BaseException as error:  # noqa: BLE001 - the event carries it
            self.emit(EVENT_AFTER_MODEL, {"error": error, "prompt": prompt})
            return None
        self.emit(EVENT_AFTER_MODEL, {"error": None, "prompt": prompt, "result": result})
        return result


# -- the snapshot hook ---------------------------------------------------

class CheckpointSnapshotHook:
    """A hook that records a marker at the model and tool boundaries.

    The hook writes a :class:`Checkpoint` marker - position and cycle
    index, nothing else.  It does not store conversation state, does not
    write a transcript, and does not decide anything: the marker it writes
    is what a later resume reads back.

    The store is a callable ``save(marker_dict) -> None`` - the caller
    decides where the marker lands.  In the runtime that would be the
    checkpoint store (``checkpoint_store.py``); this slice does not wire it,
    so the coupling stays explicit and unclaimed.
    """

    def __init__(self, *, save: Any = None, cycle_index: int = 0) -> None:
        if save is not None and not callable(save):
            raise ValueError("save must be callable")
        self._save = save
        self.cycle_index = int(cycle_index)
        self.markers: list[Checkpoint] = []

    def mark(self, position: str, *, cycle_index: int | None = None) -> Checkpoint:
        """Record a marker at ``position`` and return it."""
        if position not in POSITIONS:
            raise CheckpointException(
                f"position must be one of {POSITIONS!r}, got {position!r}"
            )
        if cycle_index is not None:
            self.cycle_index = int(cycle_index)
        marker = Checkpoint(position=position, cycle_index=self.cycle_index)
        self.markers.append(marker)
        if self._save is not None:
            self._save(marker.to_dict())
        return marker

    # -- the hook shape ----------------------------------------------------
    def after_model(self, event: Mapping[str, Any] | None = None) -> Checkpoint:
        """The ``after_model`` boundary: mark, then return the marker."""
        payload = dict(event or {})
        cycle = payload.get("cycle_index")
        return self.mark(
            POSITION_AFTER_MODEL,
            cycle_index=int(cycle) if cycle is not None else None,
        )

    def after_tools(self, event: Mapping[str, Any] | None = None) -> Checkpoint:
        """The ``after_tools`` boundary: mark, then return the marker."""
        payload = dict(event or {})
        cycle = payload.get("cycle_index")
        return self.mark(
            POSITION_AFTER_TOOLS,
            cycle_index=int(cycle) if cycle is not None else None,
        )

    def register(self) -> None:
        """Register the hook's boundaries with a hook registry."""
        # The registry lives in ``hooks.py`` and is not touched by this slice;
        # this method documents the two boundaries the hook serves.
        return None

    @property
    def last_marker(self) -> Checkpoint | None:
        """The most recent marker, or ``None`` if none was written."""
        return self.markers[-1] if self.markers else None


class ResumePlan:
    """What a resuming run should do, and from where."""

    def __init__(
        self,
        *,
        outcome: str,
        marker: Checkpoint | None = None,
        reason: str = "",
    ) -> None:
        self.outcome = outcome
        self.marker = marker
        self.reason = reason

    @property
    def resumes(self) -> bool:
        """True when the run continues from the marker."""
        return self.outcome == OUTCOME_CHECKPOINT and self.marker is not None

    @property
    def cancelled(self) -> bool:
        """True when the run was revoked and must not come back."""
        return self.outcome == OUTCOME_CANCELLED

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "marker": self.marker.to_dict() if self.marker is not None else None,
            "reason": self.reason,
        }


def plan_resume(
    marker_payload: Any = None,
    *,
    cancel: Any = None,
    interrupt: Any = NO_INTERRUPT,
) -> ResumePlan:
    """Plan a resume from a marker, honouring the kill switch.

    The marker is read with :meth:`Checkpoint.from_dict`, so a payload
    carrying state, or a version this module does not know, is refused
    here rather than half-believed.

    The order of the two questions is the whole point:

    1. **Was the run revoked?**  If so the outcome is ``"cancelled"`` and
       the marker is not used - a killed run does not come back.
    2. Otherwise, if there is a marker, the outcome is ``"checkpoint"``
       and the plan resumes from that marker's position and cycle.
    """
    outcome = resume_outcome(checkpoint=marker_payload, cancel=cancel, interrupt=interrupt)
    if outcome == OUTCOME_CANCELLED:
        return ResumePlan(
            outcome=OUTCOME_CANCELLED,
            reason="the run was cancelled; the checkpoint is not used",
        )
    if marker_payload is None:
        return ResumePlan(outcome=outcome, reason="no marker to resume from")
    marker = Checkpoint.from_dict(marker_payload)
    return ResumePlan(
        outcome=OUTCOME_CHECKPOINT,
        marker=marker,
        reason=f"resume from {marker.position} at cycle {marker.cycle_index}",
    )
