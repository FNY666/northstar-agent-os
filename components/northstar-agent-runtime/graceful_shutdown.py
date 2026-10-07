"""Graceful shutdown manager: ordered cleanup on process termination.

Research motivation: a long-running agent process holds open budgets,
audit writers, locks, and half-written state. An abrupt SIGTERM that
skips cleanup leaves a corrupt audit tail, leaked budget charges, and
unreleased locks. This module is the *cleanup ordering* half of safe
termination: the host registers cleanup hooks, the manager runs them in
reverse registration order (LIFO -- dependencies registered last tear
down first) when shutdown is requested, and every decision is recorded
for the audit trail.

Public API:

- ``ShutdownHook`` -- frozen record pinning one registered cleanup:
  ``name`` (audit identifier), ``registered_seq`` (caller-supplied int),
  and the callable itself.
- ``ShutdownManager`` -- ``register_cleanup(name, fn, seq)`` adds a
  hook; ``unregister(name)`` removes one; ``shutdown(seq)`` runs the
  hooks LIFO and returns a frozen ``ShutdownReport``.
- ``ShutdownReport`` -- frozen: ``shutdown_seq``, ``completed`` (hook
  names in run order), ``failed`` (name + error-repr pairs), and the
  ``already_shutdown`` idempotency flag.
- ``install_signal_handlers()`` / ``uninstall_signal_handlers()`` --
  wire SIGTERM/SIGINT to ``shutdown()`` on the main thread.
- ``shutdown_audit_event(report, seq)`` -- shapes the report as an
  ``audit.ndjson/1`` record.

Honest scope:

- This manager *orders and runs* cleanup; it cannot *force* a stuck
  hook to stop. Python has no safe thread-kill, so a hook that hangs
  wedges shutdown. Hosts that need hard termination must use process
  isolation (the host's job).
- Signal handlers only install on the main thread (``install_signal_handlers``
  raises ``ValueError`` elsewhere); a process killed with SIGKILL gets
  no cleanup at all -- that is by OS design, not a gap in this module.
- LIFO ordering is a convention, not a dependency solver: it assumes
  later registrations depend on earlier ones. If the host registers in
  the wrong order, the manager faithfully runs them in the wrong order.
- ``shutdown()`` never raises for hook failures; it records them and
  keeps running the rest (a failing cleanup must not wedge the ones
  after it). The host decides whether a failed cleanup is fatal.
- The signal handler runs ``shutdown()`` with an internal monotonic
  counter as the seq (there is no caller to supply one); the counter
  is process-local and deterministic.
"""

from __future__ import annotations

import signal
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

#: Version pin for this module's record shape.
GRACEFUL_SHUTDOWN_VERSION = "graceful-shutdown.v1"

#: Schema pin carried by records and audit events.
GRACEFUL_SHUTDOWN_SCHEMA = "northstar.graceful-shutdown.v1"


class ShutdownError(Exception):
    """Structural misuse of the manager (not a hook failure)."""


def _check_name(value: object, what: str = "name") -> str:
    """Validate an audit identifier: non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what} must be a non-empty string")
    return value


def _check_seq(value: object, what: str = "seq") -> int:
    """Validate a caller-supplied seq: non-bool, non-negative int."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{what} must be a non-negative int")
    return value


def _check_callable(value: object, what: str = "fn") -> Callable[[], Any]:
    """Validate a cleanup hook: must be callable."""
    if not callable(value):
        raise TypeError(f"{what} must be callable, got {type(value).__name__}")
    return value  # type: ignore[return-value]


@dataclass(frozen=True)
class ShutdownHook:
    """One registered cleanup hook."""

    name: str
    registered_seq: int
    func: Callable[[], Any]

    def __post_init__(self) -> None:
        _check_name(self.name)
        _check_seq(self.registered_seq, "registered_seq")
        _check_callable(self.func)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "registered_seq": self.registered_seq,
            "schema": GRACEFUL_SHUTDOWN_SCHEMA,
            "version": GRACEFUL_SHUTDOWN_VERSION,
        }


@dataclass(frozen=True)
class HookFailure:
    """A cleanup hook that raised; the error is a repr, never re-raised."""

    name: str
    error: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "error": self.error}


@dataclass(frozen=True)
class ShutdownReport:
    """Frozen outcome of one ``shutdown()`` call."""

    shutdown_seq: int
    completed: Tuple[str, ...]
    failed: Tuple[HookFailure, ...]
    already_shutdown: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "shutdown_seq": self.shutdown_seq,
            "completed": list(self.completed),
            "failed": [f.as_dict() for f in self.failed],
            "already_shutdown": self.already_shutdown,
            "schema": GRACEFUL_SHUTDOWN_SCHEMA,
            "version": GRACEFUL_SHUTDOWN_VERSION,
        }


class ShutdownManager:
    """Ordered cleanup registry with signal wiring.

    Thread-safe for registration and shutdown. Hooks run *outside* the
    internal lock so a hook may not call back into the manager -- the
    snapshot is taken first, then executed.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hooks: Dict[str, ShutdownHook] = {}
        self._order: List[str] = []
        self._shut_down = False
        self._signal_seq = 0
        self._previous_handlers: Dict[int, Any] = {}

    def register_cleanup(
        self, name: str, fn: Callable[[], Any], seq: int
    ) -> ShutdownHook:
        """Register a cleanup hook. Raises on duplicates or bad input."""
        with self._lock:
            if self._shut_down:
                raise ShutdownError("manager already shut down; no new hooks")
            _check_name(name)
            _check_callable(fn)
            _check_seq(seq)
            if name in self._hooks:
                raise ValueError(f"cleanup hook {name!r} already registered")
            hook = ShutdownHook(name=name, registered_seq=seq, func=fn)
            self._hooks[name] = hook
            self._order.append(name)
            return hook

    def unregister(self, name: str) -> ShutdownHook:
        """Remove a hook by name. ``KeyError`` if unknown."""
        with self._lock:
            _check_name(name)
            try:
                hook = self._hooks.pop(name)
            except KeyError:
                raise KeyError(f"no cleanup hook named {name!r}") from None
            self._order.remove(name)
            return hook

    def hooks(self) -> Tuple[ShutdownHook, ...]:
        """Registered hooks in registration order."""
        with self._lock:
            return tuple(self._hooks[n] for n in self._order)

    def is_shut_down(self) -> bool:
        with self._lock:
            return self._shut_down

    def shutdown(self, seq: int) -> ShutdownReport:
        """Run hooks in reverse registration order; never raises for hook failures.

        Idempotent: a second call returns ``already_shutdown=True`` with
        empty completed/failed tuples.
        """
        _check_seq(seq)
        with self._lock:
            if self._shut_down:
                return ShutdownReport(
                    shutdown_seq=seq,
                    completed=(),
                    failed=(),
                    already_shutdown=True,
                )
            self._shut_down = True
            snapshot = [self._hooks[n] for n in reversed(self._order)]
        completed: List[str] = []
        failed: List[HookFailure] = []
        for hook in snapshot:
            try:
                hook.func()
            except Exception as exc:  # noqa: BLE001 -- recorded, never re-raised
                failed.append(HookFailure(name=hook.name, error=repr(exc)))
            else:
                completed.append(hook.name)
        return ShutdownReport(
            shutdown_seq=seq,
            completed=tuple(completed),
            failed=tuple(failed),
            already_shutdown=False,
        )

    def install_signal_handlers(self) -> Dict[int, Any]:
        """Wire SIGTERM/SIGINT to ``shutdown()``. Main thread only.

        Returns the previous handlers (pass to ``uninstall_signal_handlers``
        to restore).
        """
        if threading.current_thread() is not threading.main_thread():
            raise ValueError("signal handlers can only be installed on the main thread")

        def _handler(signum: int, frame: Any) -> None:
            with self._lock:
                seq = self._signal_seq
                self._signal_seq += 1
            self.shutdown(seq)

        previous: Dict[int, Any] = {}
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, _handler)
        with self._lock:
            self._previous_handlers = previous
        return previous

    def uninstall_signal_handlers(self) -> Dict[int, Any]:
        """Restore the handlers saved by ``install_signal_handlers``."""
        with self._lock:
            previous = self._previous_handlers
            self._previous_handlers = {}
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        return previous


def shutdown_audit_event(report: ShutdownReport, seq: int) -> dict[str, Any]:
    """Shape a shutdown report as an ``audit.ndjson/1`` record."""
    if not isinstance(report, ShutdownReport):
        raise TypeError(
            f"report must be a ShutdownReport, got {type(report).__name__}"
        )
    _check_seq(seq, "audit seq")
    return {
        "schema": "audit.ndjson/1",
        "module": GRACEFUL_SHUTDOWN_VERSION,
        "report": report.as_dict(),
        "audit_seq": seq,
    }


def main() -> None:
    manager = ShutdownManager()
    calls: List[str] = []
    manager.register_cleanup("flush-audit", lambda: calls.append("flush-audit"), 0)
    manager.register_cleanup("release-lock", lambda: calls.append("release-lock"), 1)

    def bad_hook() -> None:
        raise RuntimeError("disk full")

    manager.register_cleanup("bad-hook", bad_hook, 2)
    report = manager.shutdown(3)
    # LIFO: bad-hook runs first and fails, the rest still run.
    assert calls == ["release-lock", "flush-audit"], calls
    assert report.completed == ("release-lock", "flush-audit")
    assert [f.name for f in report.failed] == ["bad-hook"]
    assert "disk full" in report.failed[0].error
    assert not report.already_shutdown
    second = manager.shutdown(4)
    assert second.already_shutdown and second.completed == () and second.failed == ()
    event = shutdown_audit_event(report, 5)
    assert event["schema"] == "audit.ndjson/1"
    print("graceful-shutdown OK: LIFO order, failure recorded, idempotent")


if __name__ == "__main__":
    main()
