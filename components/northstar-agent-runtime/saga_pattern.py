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

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, NoReturn, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

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


# ---------------------------------------------------------------------------
# SagaPattern: declarative step ledger (additive extension)
#
# The ``Saga`` class above *executes* caller-supplied callables. This
# section is its deterministic bookkeeping counterpart: it records which
# steps were declared, which compensations were booked, and what the
# saga's declared outcome was — frozen records, caller-supplied int seqs,
# no wall-clock, fail-closed. ``SagaPattern`` never executes a callable;
# execution outcomes live in ``Saga`` / ``SagaResult``. Both live in this
# module so one import covers orchestration and its ledger.
# ---------------------------------------------------------------------------

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Digest prefix for all pins minted by the ledger.
_DIGEST_PREFIX = "sha256:"

#: Domain separator so saga pins cannot collide with other digests.
_DIGEST_DOMAIN = b"northstar.saga-pattern.v1\x00"

#: Defensive caps: ids and descriptions are booked, not streamed.
_MAX_ID_LEN = 256
_MAX_DESC_LEN = 1024


# --- ledger errors (all subclass the module's SagaError) -------------------


class SeqOrderError(SagaError):
    """Caller seq did not strictly increase."""


class BadStepError(SagaError):
    """Step id or description failed validation."""


class DuplicateStepError(SagaError):
    """Step id already registered (ids are never recycled)."""


class UnknownStepError(SagaError):
    """No step registered with that id."""


class DuplicateCompensationError(SagaError):
    """A compensation is already booked for that step."""


class EmptySagaError(SagaError):
    """``complete()`` called with no registered steps."""


class TerminalSagaError(SagaError):
    """Mutation attempted on an already-completed saga."""


# --- ledger internals ------------------------------------------------------


def _canonical(payload: Mapping[str, Any]) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _pin(payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_DIGEST_DOMAIN + _canonical(payload)).hexdigest()
    return _DIGEST_PREFIX + digest


def _check_step_id(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadStepError(f"step_id must be a str, got {type(value).__name__}")
    if not value or len(value) > _MAX_ID_LEN:
        raise BadStepError("step_id must be non-empty and <= 256 chars")
    return value


def _check_description(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadStepError(
            f"description must be a str, got {type(value).__name__}"
        )
    if not value or len(value) > _MAX_DESC_LEN:
        raise BadStepError("description must be non-empty and <= 1024 chars")
    return value


_LEDGER_KINDS = frozenset(
    {
        "saga-pattern.step-registered",
        "saga-pattern.compensation-booked",
        "saga-pattern.completed",
        "saga-pattern.rejected",
    }
)

# Raw labels and payloads are banned from the audit boundary — only step
# ids, digest pins, and counts cross it.
_BANNED_DETAIL_KEYS = frozenset({"description", "payload", "value", "message"})


# --- ledger records --------------------------------------------------------


@dataclass(frozen=True)
class StepRecord:
    """One declared saga step, booked in registration order."""

    step_id: str
    description: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "step_id": self.step_id,
            "description": self.description,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _pin(
            {
                "step_id": self.step_id,
                "description": self.description,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class CompensationRecord:
    """A booked compensation declaration for one registered step."""

    step_id: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "step_id": self.step_id,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _pin({"step_id": self.step_id, "seq": self.seq})


@dataclass(frozen=True)
class SagaCompletion:
    """Terminal record for one saga instance's declared outcome.

    ``status`` is ``"completed"`` when no compensations were booked and
    ``"compensated"`` when at least one was — a structural summary of the
    declared bookings, never proof that a semantic rollback succeeded
    (that verdict belongs to ``Saga`` / ``SagaResult``).
    """

    saga_id: str
    status: str
    step_ids: Tuple[str, ...]
    compensated_step_ids: Tuple[str, ...]
    seq: int
    digest: str

    def __post_init__(self) -> None:
        if self.status not in ("completed", "compensated"):
            raise SagaError(f"unknown completion status: {self.status!r}")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "saga_id": self.saga_id,
            "status": self.status,
            "step_ids": list(self.step_ids),
            "compensated_step_ids": list(self.compensated_step_ids),
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _pin(
            {
                "saga_id": self.saga_id,
                "status": self.status,
                "step_ids": list(self.step_ids),
                "compensated_step_ids": list(self.compensated_step_ids),
                "seq": self.seq,
            }
        )


def saga_pattern_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the saga ledger."""
    if kind not in _LEDGER_KINDS:
        raise SagaError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    banned = _BANNED_DETAIL_KEYS.intersection(detail)
    if banned:
        raise SagaError(f"detail carries banned keys: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "saga-pattern",
        "module_version": SAGA_PATTERN_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# --- SagaPattern -----------------------------------------------------------


class SagaPattern:
    """Deterministic bookkeeping for one saga instance's declared steps.

    Distinct from :class:`Saga` (which runs callables): this ledger only
    *books* — which steps were declared (``step``), which compensations
    were booked (``compensate``), and the declared outcome
    (``complete``). All mutations take a caller-supplied strictly
    increasing ``seq``; failed mutations consume their seq and book a
    ``saga-pattern.rejected`` audit row (batch discipline). ``complete``
    is terminal; later mutations raise :class:`TerminalSagaError`.
    Views consume no seq and write no audit rows.
    """

    def __init__(self, saga_id: str):
        self._saga_id = _check_text(saga_id, "saga_id")
        self._lock = threading.RLock()
        self._last_seq = -1
        self._steps: Dict[str, StepRecord] = {}
        self._compensations: Dict[str, CompensationRecord] = {}
        self._completion: SagaCompletion | None = None
        self._audit: list[Mapping[str, Any]] = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)  # malformed seq raises, consumes nothing
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must strictly increase (last={self._last_seq}, got={seq})"
                )
            self._last_seq = seq
        return seq

    def _fail(
        self, seq: int, exc: SagaError, **detail: Any
    ) -> "NoReturn":
        """Book a rejection audit row, then raise the given error."""
        # ``seq`` is already claimed by the caller path; record the refusal.
        with self._lock:
            self._audit.append(
                saga_pattern_audit_event(
                    "saga-pattern.rejected", seq, reason=str(exc), **detail
                )
            )
        raise exc

    def _ensure_live(self, seq: int) -> None:
        if self._completion is not None:
            self._fail(
                seq,
                TerminalSagaError("saga already completed"),
                saga_id=self._saga_id,
            )

    # -- views ------------------------------------------------------------

    def step_record(self, step_id: str) -> StepRecord:
        """Pure read view of one registered step."""
        step_id = _check_step_id(step_id)
        with self._lock:
            try:
                return self._steps[step_id]
            except KeyError:
                raise UnknownStepError(
                    f"no such step: {step_id!r}"
                ) from None

    def compensation_record(self, step_id: str) -> CompensationRecord:
        """Pure read view of one booked compensation."""
        step_id = _check_step_id(step_id)
        with self._lock:
            try:
                return self._compensations[step_id]
            except KeyError:
                raise UnknownStepError(
                    f"no compensation booked for step: {step_id!r}"
                ) from None

    def step_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._steps))

    def compensated_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._compensations))

    def completion(self) -> "SagaCompletion | None":
        """The terminal record, or ``None`` before ``complete()``."""
        with self._lock:
            return self._completion

    def stats(self) -> Mapping[str, Any]:
        with self._lock:
            return {
                "steps": len(self._steps),
                "compensations": len(self._compensations),
                "completed": self._completion is not None,
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    # -- mutations ----------------------------------------------------------

    def step(self, step_id: str, description: str, seq: int) -> StepRecord:
        """Declare one saga step. Duplicate ids are refused fail-closed."""
        step_id = _check_step_id(step_id)
        description = _check_description(description)
        seq = self._claim(seq)
        self._ensure_live(seq)
        with self._lock:
            if step_id in self._steps:
                self._fail(
                    seq,
                    DuplicateStepError(
                        f"step id already registered: {step_id!r}"
                    ),
                    step_id=step_id,
                )
            record = StepRecord(
                step_id=step_id,
                description=description,
                seq=seq,
                digest=_pin(
                    {
                        "step_id": step_id,
                        "description": description,
                        "seq": seq,
                    }
                ),
            )
            self._steps[step_id] = record
            self._audit.append(
                saga_pattern_audit_event(
                    "saga-pattern.step-registered",
                    seq,
                    step_id=step_id,
                    digest=record.digest,
                )
            )
            return record

    def compensate(self, step_id: str, seq: int) -> CompensationRecord:
        """Book a compensation declaration for a registered step."""
        step_id = _check_step_id(step_id)
        seq = self._claim(seq)
        self._ensure_live(seq)
        with self._lock:
            if step_id not in self._steps:
                self._fail(
                    seq,
                    UnknownStepError(f"no such step: {step_id!r}"),
                    step_id=step_id,
                )
            if step_id in self._compensations:
                self._fail(
                    seq,
                    DuplicateCompensationError(
                        f"compensation already booked: {step_id!r}"
                    ),
                    step_id=step_id,
                )
            record = CompensationRecord(
                step_id=step_id,
                seq=seq,
                digest=_pin({"step_id": step_id, "seq": seq}),
            )
            self._compensations[step_id] = record
            self._audit.append(
                saga_pattern_audit_event(
                    "saga-pattern.compensation-booked",
                    seq,
                    step_id=step_id,
                    digest=record.digest,
                )
            )
            return record

    def complete(self, seq: int) -> SagaCompletion:
        """Terminally book the saga's declared outcome.

        ``status`` is ``"compensated"`` when at least one compensation was
        booked, otherwise ``"completed"``. Booking a compensation declares
        that the backward path was taken for that step; the status is a
        structural summary of these bookings, not proof of semantic
        rollback.
        """
        seq = self._claim(seq)
        self._ensure_live(seq)
        with self._lock:
            if not self._steps:
                self._fail(seq, EmptySagaError("complete() with no steps"))
            step_ids = tuple(sorted(self._steps))
            compensated_ids = tuple(sorted(self._compensations))
            status = "compensated" if compensated_ids else "completed"
            record = SagaCompletion(
                saga_id=self._saga_id,
                status=status,
                step_ids=step_ids,
                compensated_step_ids=compensated_ids,
                seq=seq,
                digest=_pin(
                    {
                        "saga_id": self._saga_id,
                        "status": status,
                        "step_ids": list(step_ids),
                        "compensated_step_ids": list(compensated_ids),
                        "seq": seq,
                    }
                ),
            )
            self._completion = record
            self._audit.append(
                saga_pattern_audit_event(
                    "saga-pattern.completed",
                    seq,
                    saga_id=self._saga_id,
                    status=status,
                    steps=len(step_ids),
                    compensated=len(compensated_ids),
                    digest=record.digest,
                )
            )
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

    # Declarative ledger: steps, compensation booking, completion verdict.
    ledger = SagaPattern("ledger-1")
    r1 = ledger.step("s1", "first", 0)
    assert r1.verify()
    ledger.step("s2", "second", 1)
    ledger.compensate("s1", 2)
    done = ledger.complete(3)
    assert done.status == "compensated", done
    assert done.compensated_step_ids == ("s1",), done
    assert done.verify()
    try:
        ledger.step("s3", "late", 4)
    except TerminalSagaError:
        pass
    else:  # pragma: no cover
        raise AssertionError("mutation after complete must be refused")

    ledger2 = SagaPattern("ledger-2")
    ledger2.step("only", "single step", 0)
    done2 = ledger2.complete(1)
    assert done2.status == "completed", done2
    assert done2.verify()

    print("saga-pattern OK: completed, compensated, compensation-failure, ledger")


if __name__ == "__main__":
    main()
