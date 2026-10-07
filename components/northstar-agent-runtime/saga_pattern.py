"""Saga pattern: distributed-transaction orchestration with compensations.

Research note: the saga pattern (Garcia-Molina & Salem, 1987; popularized
for microservices by Nygard, *Release It!*) breaks a long-lived transaction
into a sequence of local steps, each with a *compensating action* that
semantically undoes it. When a step fails, the saga runs the compensations
of the already-completed steps in reverse order — the closest thing a
distributed system gets to atomic rollback.

* **Forward path** — steps run in registration order. Each step's action
  is a caller-supplied callable; the saga records ``step-started`` /
  ``step-completed`` events around it.
* **Backward path** — on the first step failure the saga stops the forward
  path and runs compensations for the completed steps in *reverse* order.
  Compensations are best-effort: a failing compensation is recorded
  (``compensation-failed``) and the saga continues with the remaining
  compensations, because abandoning the rollback half-done is worse.
* **Outcome vocabulary** — ``completed`` (all steps ran), ``compensated``
  (a step failed, every compensation ran clean), ``failed`` (a step failed
  *and* at least one compensation failed — the system may be left in a
  partially-rolled-back state, which the host must reconcile manually).
* **No wall-clock** — all ordering uses caller-supplied int ``seq`` values,
  so the module is deterministic and replayable.
* **Fail-closed** — malformed steps, non-callable actions, duplicate step
  ids, and empty sagas raise at construction/execution time; they are never
  silently skipped.

Honest scope: this is the *orchestration* of compensating actions, not a
guarantee of consistency — a compensation is a semantic undo written by
the caller, and the saga cannot verify that it truly reversed the step's
effects. ``compensated`` means "every compensation ran without raising",
never "the world is exactly as it was". Steps that already executed
outside the saga (pre-trigger work, like the kill-switch caveat) are not
unwound. Concurrent sagas sharing mutable state must serialize at the host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Tuple

#: Module version.
SAGA_PATTERN_VERSION = "saga-pattern.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.saga-pattern.v1"


class SagaError(Exception):
    """Malformed input to the saga (programming error)."""


class SagaStepError(Exception):
    """A step's action raised; carries the step id and the original error."""

    def __init__(self, step_id: str, original: BaseException):
        self.step_id = step_id
        self.original = original
        super().__init__(f"saga step {step_id!r} failed: {original!r}")


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SagaError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SagaError(f"{name} must be non-negative")
    return seq


def _check_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SagaError(f"{name} must be a non-empty str")
    return value


@dataclass(frozen=True)
class SagaStep:
    """One step of a saga: a forward action plus its compensation.

    ``action`` runs the step; ``compensation`` semantically undoes it and
    is only ever invoked for steps whose action completed. Both are
    caller-supplied callables taking no arguments.
    """

    step_id: str
    description: str
    action: Callable[[], Any]
    compensation: Callable[[], Any]

    def __post_init__(self) -> None:
        _check_text(self.step_id, "step_id")
        _check_text(self.description, "description")
        if not callable(self.action):
            raise SagaError("action must be callable")
        if not callable(self.compensation):
            raise SagaError("compensation must be callable")


@dataclass(frozen=True)
class SagaEvent:
    """One recorded occurrence during saga execution."""

    kind: str  # see _EVENT_KINDS
    step_id: str
    seq: int
    detail: str = ""

    def __post_init__(self) -> None:
        if self.kind not in _EVENT_KINDS:
            raise SagaError(f"unknown event kind: {self.kind!r}")
        _check_seq(self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "kind": self.kind,
            "step_id": self.step_id,
            "seq": self.seq,
            "detail": self.detail,
        }


_EVENT_KINDS = frozenset(
    {
        "saga-started",
        "step-started",
        "step-completed",
        "step-failed",
        "compensation-started",
        "compensation-completed",
        "compensation-failed",
        "saga-completed",
        "saga-compensated",
        "saga-failed",
    }
)


@dataclass(frozen=True)
class SagaResult:
    """The outcome of ``Saga.execute``.

    ``status`` is one of ``"completed"`` (all steps ran), ``"compensated"``
    (a step failed; every compensation ran clean), or ``"failed"`` (a step
    failed and at least one compensation also failed).
    """

    status: str
    saga_id: str
    completed_step_ids: Tuple[str, ...]
    compensated_step_ids: Tuple[str, ...]
    failed_step_id: str
    failed_compensation_ids: Tuple[str, ...]
    error: str

    def __post_init__(self) -> None:
        if self.status not in ("completed", "compensated", "failed"):
            raise SagaError(f"unknown saga status: {self.status!r}")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "status": self.status,
            "saga_id": self.saga_id,
            "completed_step_ids": list(self.completed_step_ids),
            "compensated_step_ids": list(self.compensated_step_ids),
            "failed_step_id": self.failed_step_id,
            "failed_compensation_ids": list(self.failed_compensation_ids),
            "error": self.error,
        }


class Saga:
    """A named sequence of steps with compensating actions."""

    def __init__(self, saga_id: str, steps: Tuple[SagaStep, ...] | list[SagaStep]):
        self._saga_id = _check_text(saga_id, "saga_id")
        if not isinstance(steps, (tuple, list)) or not steps:
            raise SagaError("steps must be a non-empty tuple/list of SagaStep")
        seen: set[str] = set()
        for step in steps:
            if not isinstance(step, SagaStep):
                raise SagaError(
                    f"steps must contain SagaStep, got {type(step).__name__}"
                )
            if step.step_id in seen:
                raise SagaError(f"duplicate step_id: {step.step_id!r}")
            seen.add(step.step_id)
        self._steps: Tuple[SagaStep, ...] = tuple(steps)
        self._events: list[SagaEvent] = []

    @property
    def saga_id(self) -> str:
        return self._saga_id

    @property
    def steps(self) -> Tuple[SagaStep, ...]:
        return self._steps

    def events(self) -> Tuple[SagaEvent, ...]:
        """Append-only event log in execution order."""
        return tuple(self._events)

    def _record(self, kind: str, step_id: str, seq: int, detail: str = "") -> None:
        self._events.append(SagaEvent(kind=kind, step_id=step_id, seq=seq, detail=detail))

    def execute(self, seq: int) -> SagaResult:
        """Run the saga.

        ``seq`` is the caller-supplied starting sequence number; each
        recorded event consumes one seq in order. Returns a frozen
        ``SagaResult``; the step's original exception is surfaced in the
        result's ``error`` field (and wrapped in ``SagaStepError`` only for
        the ``failed_step_id`` bookkeeping — ``execute`` itself never raises
        for step failures, only for malformed input).
        """
        _check_seq(seq, "seq")
        cur = seq
        self._record("saga-started", "", cur)
        cur += 1

        completed: list[SagaStep] = []
        for step in self._steps:
            self._record("step-started", step.step_id, cur)
            cur += 1
            try:
                step.action()
            except Exception as exc:  # noqa: BLE001 - step failure is the trigger
                self._record("step-failed", step.step_id, cur, detail=repr(exc))
                cur += 1
                return self._compensate(completed, step.step_id, repr(exc), cur)
            self._record("step-completed", step.step_id, cur)
            cur += 1
            completed.append(step)

        self._record("saga-completed", "", cur)
        return SagaResult(
            status="completed",
            saga_id=self._saga_id,
            completed_step_ids=tuple(s.step_id for s in completed),
            compensated_step_ids=(),
            failed_step_id="",
            failed_compensation_ids=(),
            error="",
        )

    def _compensate(
        self,
        completed: list[SagaStep],
        failed_step_id: str,
        error: str,
        seq: int,
    ) -> SagaResult:
        cur = seq
        compensated: list[str] = []
        failed_compensations: list[str] = []
        for step in reversed(completed):
            self._record("compensation-started", step.step_id, cur)
            cur += 1
            try:
                step.compensation()
            except Exception as exc:  # noqa: BLE001 - best-effort rollback
                self._record(
                    "compensation-failed", step.step_id, cur, detail=repr(exc)
                )
                cur += 1
                failed_compensations.append(step.step_id)
                continue
            self._record("compensation-completed", step.step_id, cur)
            cur += 1
            compensated.append(step.step_id)

        if failed_compensations:
            self._record("saga-failed", "", cur, detail="compensation failed")
            status = "failed"
        else:
            self._record("saga-compensated", "", cur)
            status = "compensated"
        return SagaResult(
            status=status,
            saga_id=self._saga_id,
            completed_step_ids=tuple(s.step_id for s in completed),
            compensated_step_ids=tuple(compensated),
            failed_step_id=failed_step_id,
            failed_compensation_ids=tuple(failed_compensations),
            error=error,
        )


def saga_audit_event(result: SagaResult, seq: int) -> dict:
    """Shape a ``SagaResult`` as an ``audit.ndjson/1``-style record."""
    _check_seq(seq, "seq")
    if not isinstance(result, SagaResult):
        raise SagaError(f"result must be SagaResult, got {type(result).__name__}")
    record = result.as_dict()
    record["audit_seq"] = seq
    return record


def main() -> None:
    log: list[str] = []

    def ok(name: str) -> Callable[[], None]:
        def _run() -> None:
            log.append(name)

        return _run

    def boom(name: str) -> Callable[[], None]:
        def _run() -> None:
            log.append(name)
            raise RuntimeError(f"{name} exploded")

        return _run

    # Happy path.
    saga = Saga(
        "saga-happy",
        (
            SagaStep("s1", "first", ok("a1"), ok("c1")),
            SagaStep("s2", "second", ok("a2"), ok("c2")),
        ),
    )
    result = saga.execute(0)
    assert result.status == "completed", result
    assert log == ["a1", "a2"], log

    # Failure path: s2 fails, s1 is compensated in reverse order.
    log.clear()
    saga2 = Saga(
        "saga-sad",
        (
            SagaStep("s1", "first", ok("a1"), ok("c1")),
            SagaStep("s2", "second", boom("a2"), ok("c2")),
            SagaStep("s3", "third", ok("a3"), ok("c3")),
        ),
    )
    result2 = saga2.execute(100)
    assert result2.status == "compensated", result2
    assert result2.failed_step_id == "s2", result2
    assert log == ["a1", "a2", "c1"], log
    # s3 never ran.
    assert result2.completed_step_ids == ("s1",), result2

    # Compensation failure: saga ends "failed", not "compensated".
    log.clear()
    saga3 = Saga(
        "saga-broken",
        (
            SagaStep("s1", "first", ok("a1"), boom("c1")),
            SagaStep("s2", "second", boom("a2"), ok("c2")),
        ),
    )
    result3 = saga3.execute(200)
    assert result3.status == "failed", result3
    assert result3.failed_compensation_ids == ("s1",), result3

    print("saga-pattern OK: completed, compensated, compensation-failure")


if __name__ == "__main__":
    main()
