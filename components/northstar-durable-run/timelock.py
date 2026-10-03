"""Timelock-delayed execution for irreversible-tier tool calls.

Absorbed mechanism: OpenZeppelin ``TimelockController``
(``contracts/governance/TimelockController.sol``, MIT) — schedule an
operation, wait out a delay, then execute; the host may cancel while the
operation is pending. The semantics below were verified against the actual
contract source:

* ``OperationState``: ``Unset``, ``Waiting``, ``Ready``, ``Done``, derived
  from a single timestamp (0 = unset, 1 = done, future = waiting,
  past-or-now = ready).
* The operation id is the hash of the *exact* call parameters
  (``hashOperation`` binds target/value/data/predecessor/salt): ``execute``
  recomputes the id from the presented parameters, so tampered parameters
  address a different (unset) id and fail the readiness check.
* ``cancel`` requires the operation to be pending (``Waiting`` or
  ``Ready``); it deletes the timestamp and emits ``Cancelled``.
* ``execute`` requires ``Ready`` (``_beforeCall``), runs the call, then
  marks the operation done (``_afterCall`` re-checks ``Ready`` to close
  reentrancy).
* ``schedule`` requires the id to be unset and the delay to be at least
  ``minDelay``.

Deliberate adaptations for this offline deterministic engine:

1. Time is an explicit integer ``now`` parameter (seconds), never
   ``block.timestamp`` — the engine is deterministic and simulated time
   must be injectable.
2. ``cancelled`` is a persistent terminal state instead of deleting the
   timestamp back to ``Unset``: a cancelled operation id can never be
   re-scheduled (fail-closed), and the state itself keeps the full
   schedule→cancelled transition. OZ relies on the ``Cancelled`` event for
   the trail; here the state is the trail.
3. Execution is split into :meth:`Timelock.authorize_execute` (the
   ``_beforeCall`` analog) and :meth:`Timelock.mark_executed` (the
   ``_afterCall`` analog) so the host's executor runs between them: a
   failed executor leaves the operation ``Ready`` (retryable); a
   successful one moves it to ``Done``.
4. No predecessor chaining and no on-chain role system: the host's
   existing approval (:class:`ActionGateway`) is the authorization, and the
   host identity that cancels is recorded in the audit event. The
   ``ActionGateway`` wires the timelock to the irreversible tool tier:
   schedule happens host-side (after approval), execute passes the
   operation id and is gated on ``Ready``.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

TIMELOCK_SCHEMA_VERSION = "northstar.timelock.v1"

OPERATION_UNSET = "unset"
OPERATION_WAITING = "waiting"
OPERATION_READY = "ready"
OPERATION_DONE = "done"
OPERATION_CANCELLED = "cancelled"

_ID_RE = re.compile(r"^[^\s/\\]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_NONCE_BYTES = 32


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("value is not canonical JSON") from error


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _require_digest(value: Any, field: str = "arguments_digest") -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


def _require_now(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("now must be an integer")
    if value < 0:
        raise ValueError("now must be non-negative")
    return value


def _require_delay(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if value <= 0:
        raise ValueError(f"{field} must be positive")
    return value


def hash_operation(
    tool_name: str, arguments_digest: str, call_ref: str, nonce: str
) -> str:
    """Deterministic operation id, the ``hashOperation`` analog.

    Binds the exact tool identity, the parameter digest, a caller-chosen
    call reference, and a nonce (the ``salt`` analog): presenting different
    parameters at execution time addresses a different id, which is unset
    and therefore never ready.
    """
    _require_id(tool_name, "tool_name")
    _require_digest(arguments_digest)
    _require_id(call_ref, "call_ref")
    _require_id(nonce, "nonce")
    body = _canonical_json(
        {
            "schema_version": TIMELOCK_SCHEMA_VERSION,
            "tool_name": tool_name,
            "arguments_digest": arguments_digest,
            "call_ref": call_ref,
            "nonce": nonce,
        }
    )
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class TimelockOperation:
    """One scheduled operation. Immutable; the timelock owns the state."""

    operation_id: str
    tool_name: str
    arguments_digest: str
    call_ref: str
    nonce: str
    scheduled_at: int
    ready_at: int
    state: str


class Timelock:
    """Schedule → wait → execute state machine for irreversible operations.

    ``audit`` receives one dict per state transition (``scheduled``,
    ``cancelled``, ``executed``) so the host can chain them into the audit
    feed; the timelock itself never touches the network or the clock.

    Not thread-safe: drive one call at a time per instance.
    """

    def __init__(
        self,
        *,
        min_delay_s: int = 300,
        audit: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._min_delay_s = _require_delay(min_delay_s, "min_delay_s")
        if audit is not None and not callable(audit):
            raise ValueError("audit must be callable")
        self._audit = audit
        self._operations: dict[str, TimelockOperation] = {}

    @property
    def min_delay_s(self) -> int:
        return self._min_delay_s

    def _emit(self, event: dict[str, Any]) -> None:
        if self._audit is not None:
            self._audit(event)

    def _state_at(self, operation: TimelockOperation, now: int) -> str:
        if operation.state in (OPERATION_DONE, OPERATION_CANCELLED):
            return operation.state
        if now >= operation.ready_at:
            return OPERATION_READY
        return OPERATION_WAITING

    def state(self, operation_id: str, *, now: int) -> str:
        """Current state of an operation (``unset`` when unknown)."""
        _require_now(now)
        operation = self._operations.get(operation_id)
        if operation is None:
            return OPERATION_UNSET
        return self._state_at(operation, now)

    def get(self, operation_id: str) -> TimelockOperation | None:
        return self._operations.get(operation_id)

    def schedule(
        self,
        *,
        tool_name: str,
        arguments_digest: str,
        call_ref: str,
        delay_s: int,
        now: int,
        nonce: str | None = None,
    ) -> TimelockOperation:
        """Schedule an operation; it becomes ready at ``now + delay_s``.

        Mirrors OZ ``_schedule``: the id must be unset (a cancelled or done
        id stays claimed — fail-closed, never silently re-scheduled) and
        the delay must be at least the minimum.
        """
        _require_id(tool_name, "tool_name")
        _require_digest(arguments_digest)
        _require_id(call_ref, "call_ref")
        _require_delay(delay_s, "delay_s")
        _require_now(now)
        if delay_s < self._min_delay_s:
            raise ValueError(
                f"timelock delay {delay_s}s is below the minimum {self._min_delay_s}s"
            )
        if nonce is None:
            nonce = secrets.token_hex(_MAX_NONCE_BYTES // 2)
        _require_id(nonce, "nonce")
        operation_id = hash_operation(tool_name, arguments_digest, call_ref, nonce)
        if operation_id in self._operations:
            raise ValueError("timelock operation id is already scheduled")
        operation = TimelockOperation(
            operation_id=operation_id,
            tool_name=tool_name,
            arguments_digest=arguments_digest,
            call_ref=call_ref,
            nonce=nonce,
            scheduled_at=now,
            ready_at=now + delay_s,
            state=OPERATION_WAITING,
        )
        self._operations[operation_id] = operation
        self._emit(
            {
                "schema_version": TIMELOCK_SCHEMA_VERSION,
                "event_type": "timelock.scheduled",
                "operation_id": operation_id,
                "tool_name": tool_name,
                "arguments_digest": arguments_digest,
                "call_ref": call_ref,
                "scheduled_at": now,
                "ready_at": now + delay_s,
                "delay_s": delay_s,
            }
        )
        return operation

    def cancel(
        self, operation_id: str, *, now: int, cancelled_by: str
    ) -> TimelockOperation:
        """Cancel a pending operation (``waiting`` or ``ready``).

        Mirrors OZ ``cancel`` (pending-only); the record is kept as
        ``cancelled`` instead of being deleted, so the id stays claimed.
        """
        _require_now(now)
        _require_id(cancelled_by, "cancelled_by")
        operation = self._operations.get(operation_id)
        if operation is None:
            raise ValueError("timelock operation is unknown")
        state = self._state_at(operation, now)
        if state not in (OPERATION_WAITING, OPERATION_READY):
            raise ValueError(
                f"timelock operation cannot be cancelled from state {state!r}"
            )
        cancelled = TimelockOperation(
            operation_id=operation.operation_id,
            tool_name=operation.tool_name,
            arguments_digest=operation.arguments_digest,
            call_ref=operation.call_ref,
            nonce=operation.nonce,
            scheduled_at=operation.scheduled_at,
            ready_at=operation.ready_at,
            state=OPERATION_CANCELLED,
        )
        self._operations[operation_id] = cancelled
        self._emit(
            {
                "schema_version": TIMELOCK_SCHEMA_VERSION,
                "event_type": "timelock.cancelled",
                "operation_id": operation_id,
                "cancelled_by": cancelled_by,
                "cancelled_at": now,
                "was_state": state,
            }
        )
        return cancelled

    def authorize_execute(
        self,
        operation_id: str,
        *,
        tool_name: str,
        arguments_digest: str,
        now: int,
    ) -> TimelockOperation:
        """The ``_beforeCall`` analog: allow execution only when ready.

        Requires the operation to be ``ready`` (delay elapsed) *and* the
        presented tool name and parameter digest to match the scheduled
        ones — the binding OZ gets from recomputing the operation id.
        Does not change state; call :meth:`mark_executed` after the
        executor returns.
        """
        _require_now(now)
        _require_id(tool_name, "tool_name")
        _require_digest(arguments_digest)
        operation = self._operations.get(operation_id)
        if operation is None:
            raise ValueError("timelock operation is unknown")
        state = self._state_at(operation, now)
        if state != OPERATION_READY:
            raise ValueError(
                f"timelock operation is not ready (state {state!r})"
            )
        if operation.tool_name != tool_name:
            raise ValueError("timelock operation does not match tool name")
        if operation.arguments_digest != arguments_digest:
            raise ValueError("timelock operation does not match arguments digest")
        return operation

    def mark_executed(self, operation_id: str, *, now: int) -> TimelockOperation:
        """The ``_afterCall`` analog: move a ready operation to ``done``.

        Re-checks ``ready`` (mirroring OZ's post-execution state check) so
        a cancelled-between-authorize-and-mark operation cannot be marked
        done.
        """
        _require_now(now)
        operation = self._operations.get(operation_id)
        if operation is None:
            raise ValueError("timelock operation is unknown")
        state = self._state_at(operation, now)
        if state != OPERATION_READY:
            raise ValueError(
                f"timelock operation cannot be marked executed from state {state!r}"
            )
        done = TimelockOperation(
            operation_id=operation.operation_id,
            tool_name=operation.tool_name,
            arguments_digest=operation.arguments_digest,
            call_ref=operation.call_ref,
            nonce=operation.nonce,
            scheduled_at=operation.scheduled_at,
            ready_at=operation.ready_at,
            state=OPERATION_DONE,
        )
        self._operations[operation_id] = done
        self._emit(
            {
                "schema_version": TIMELOCK_SCHEMA_VERSION,
                "event_type": "timelock.executed",
                "operation_id": operation_id,
                "executed_at": now,
            }
        )
        return done
