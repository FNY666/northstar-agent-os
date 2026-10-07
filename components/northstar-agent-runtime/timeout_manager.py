"""Safety timeout manager: enforce wall-clock deadlines on untrusted work.

Research motivation: a timeout is the cheapest safety primitive -- when a
model call, tool invocation, or sub-agent fails to terminate, the bounded
system must stop *waiting* rather than hang forever. This module is the
deadline layer only: it refuses to wait past a deadline and raises
:exc:`TimeoutExceeded` so the caller can fail closed (deny the action,
trigger the kill switch, escalate to a human).

Public API:

- ``Timeout`` -- frozen record pinning a deadline: ``name`` (audit
  identifier), ``duration`` (strictly positive real seconds), and
  ``action`` (what the host should do when the deadline fires: one of
  ``ACTION_DENY``, ``ACTION_KILL``, ``ACTION_ESCALATE``).
- ``TimeoutExceeded`` -- exception raised when a deadline fires; carries
  the ``Timeout`` record that fired.
- ``TimeoutManager`` -- ``deadline_for(timeout)`` mints a deadline from
  ``time.monotonic()``; ``expired(deadline)`` / ``remaining(deadline)``
  evaluate it; ``run_with_timeout(func, timeout, *args, **kwargs)``
  runs ``func`` in a worker thread and returns its result, or raises
  ``TimeoutExceeded`` if the deadline fires first.

Honest scope:

- This manager refuses to *wait* past a deadline; it cannot *stop* the
  timed-out work. Python has no safe thread-kill, so a function that
  ignores its deadline keeps running in a daemon worker thread until it
  finishes or the process exits. Daemon threads are used precisely so a
  runaway worker cannot wedge interpreter shutdown. Callers that need
  hard termination must use process isolation (the host's job).
- Deadlines use ``time.monotonic()`` (immune to NTP jumps), not
  ``time.time()``. Monotonic is the strictly more robust choice for
  safety deadlines; the wall-clock SLA variant (``approval_sla_time``)
  documents the opposite trade-off explicitly.
- An exception raised by ``func`` itself propagates unchanged -- it is
  the function's own failure, never converted into ``TimeoutExceeded``.
- This is a deadline layer, not a scheduler: no retries, no priority,
  no cancellation tokens.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

#: Version pin for this module's record shape.
TIMEOUT_MANAGER_VERSION = "timeout-manager.v1"

#: Schema pin carried by records and audit events.
TIMEOUT_SCHEMA = "northstar.timeout-manager.v1"

#: Timeout actions: what the host should do when the deadline fires.
ACTION_DENY = "deny"
ACTION_KILL = "kill"
ACTION_ESCALATE = "escalate"

_ACTIONS = frozenset({ACTION_DENY, ACTION_KILL, ACTION_ESCALATE})

#: Outcomes reported in audit events.
OUTCOME_COMPLETED = "completed"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_FAILED = "failed"

_OUTCOMES = frozenset({OUTCOME_COMPLETED, OUTCOME_TIMEOUT, OUTCOME_FAILED})


def _check_duration(value: object, name: str = "duration") -> float:
    """Validate a duration: real number, not bool, strictly positive."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    duration = float(value)
    if duration <= 0:
        raise ValueError(f"{name} must be strictly positive, got {duration}")
    return duration


def _check_deadline(value: object, name: str = "deadline") -> float:
    """Validate a monotonic deadline timestamp: real number, not bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    return float(value)


@dataclass(frozen=True)
class Timeout:
    """A pinned safety deadline.

    ``duration`` is strictly positive real seconds; ``action`` names the
    host's required response when the deadline fires (``deny`` /
    ``kill`` / ``escalate``); ``name`` is a non-empty audit identifier.
    """

    name: str
    duration: float
    action: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("name must be a non-empty string")
        object.__setattr__(self, "duration", _check_duration(self.duration))
        if self.action not in _ACTIONS:
            raise ValueError(
                f"action must be one of {sorted(_ACTIONS)}, got {self.action!r}"
            )

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe record shape."""
        return {
            "schema": TIMEOUT_SCHEMA,
            "version": TIMEOUT_MANAGER_VERSION,
            "name": self.name,
            "duration": self.duration,
            "action": self.action,
        }


class TimeoutExceeded(Exception):
    """Raised when a deadline fires before the work finished.

    Carries the :class:`Timeout` record that fired in ``.timeout`` so
    the caller can apply the recorded ``action`` (deny / kill /
    escalate) without guessing.
    """

    def __init__(self, timeout: Timeout) -> None:
        if not isinstance(timeout, Timeout):
            raise TypeError(
                f"timeout must be a Timeout, got {type(timeout).__name__}"
            )
        self.timeout = timeout
        super().__init__(
            f"timeout {timeout.name!r} exceeded after "
            f"{timeout.duration}s (action: {timeout.action})"
        )


class TimeoutManager:
    """Mint and enforce monotonic deadlines; run work under a deadline."""

    def deadline_for(self, timeout: Timeout) -> float:
        """Return the monotonic timestamp at which ``timeout`` fires."""
        if not isinstance(timeout, Timeout):
            raise TypeError(
                f"timeout must be a Timeout, got {type(timeout).__name__}"
            )
        return time.monotonic() + timeout.duration

    def expired(self, deadline: float) -> bool:
        """Return True if the monotonic clock has reached ``deadline``."""
        _check_deadline(deadline)
        return time.monotonic() >= deadline

    def remaining(self, deadline: float) -> float:
        """Return seconds left until ``deadline``; 0.0 once expired."""
        _check_deadline(deadline)
        return max(0.0, deadline - time.monotonic())

    def run_with_timeout(
        self,
        func: Callable[..., Any],
        timeout: Timeout,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Run ``func(*args, **kwargs)``; return its result or raise.

        Returns the function's result when it finishes before the
        deadline. Raises :exc:`TimeoutExceeded` when the deadline fires
        first. An exception raised by ``func`` itself propagates
        unchanged.

        The work runs in a daemon worker thread: on timeout the manager
        stops waiting, but the thread itself cannot be killed and may
        still be running. Daemon threads never block interpreter exit.
        """
        if not callable(func):
            raise TypeError(f"func must be callable, got {type(func).__name__}")
        if not isinstance(timeout, Timeout):
            raise TypeError(
                f"timeout must be a Timeout, got {type(timeout).__name__}"
            )

        outcome: dict[str, Any] = {}
        done = threading.Event()

        def _worker() -> None:
            try:
                outcome["result"] = func(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001 -- must capture everything
                outcome["error"] = exc
            finally:
                done.set()

        worker = threading.Thread(target=_worker, daemon=True)
        worker.start()
        finished = done.wait(timeout.duration)
        if not finished:
            raise TimeoutExceeded(timeout)
        if "error" in outcome:
            raise outcome["error"]
        return outcome.get("result")


def timeout_audit_event(
    timeout: Timeout, outcome: str, seq: int
) -> dict[str, Any]:
    """Shape a timeout decision as an ``audit.ndjson/1`` record."""
    if not isinstance(timeout, Timeout):
        raise TypeError(
            f"timeout must be a Timeout, got {type(timeout).__name__}"
        )
    if outcome not in _OUTCOMES:
        raise ValueError(
            f"outcome must be one of {sorted(_OUTCOMES)}, got {outcome!r}"
        )
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return {
        "schema": "audit.ndjson/1",
        "module": TIMEOUT_MANAGER_VERSION,
        "timeout": timeout.as_dict(),
        "outcome": outcome,
        "audit_seq": seq,
    }


def main() -> None:
    manager = TimeoutManager()
    timeout = Timeout(name="model-call", duration=5.0, action=ACTION_DENY)
    assert manager.run_with_timeout(lambda: 42, timeout) == 42
    deadline = manager.deadline_for(timeout)
    assert not manager.expired(deadline)
    assert manager.remaining(deadline) > 0
    quick = Timeout(name="slow-tool", duration=0.05, action=ACTION_KILL)
    try:
        manager.run_with_timeout(time.sleep, quick, 10.0)
    except TimeoutExceeded as exc:
        assert exc.timeout is quick
    else:  # pragma: no cover -- must raise
        raise AssertionError("expected TimeoutExceeded")
    event = timeout_audit_event(timeout, OUTCOME_COMPLETED, 7)
    assert event["schema"] == "audit.ndjson/1"
    print("timeout-manager OK: run/expire/audit")


if __name__ == "__main__":
    main()
