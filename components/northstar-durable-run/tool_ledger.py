"""Three-state tool-effect ledger for durable resume.

Tinyagents-style ledger: every tool effect is identified by
``(run_id, tool_call_id)`` and moves through ``started -> completed`` (or
``started -> failed``). Each transition is a first-class event in the
EventStore (``tool.started`` / ``tool.completed`` / ``tool.failed``, see
``durable_contract._EVENT_STATUS_BY_TYPE``); replayable results are cached in
a small sidecar file next to the event history.

Exactly-once, stated honestly (the DeepTrace conclusion)
--------------------------------------------------------
The ledger gives you:

- at-most-once *replay from its own records*: a ``completed`` tool call is
  never re-executed from the ledger — its cached result is returned;
- at-least-once *effect application*: a ``started``-without-``completed``
  tool call is re-issued, because the effect may never have happened.

End-to-end exactly-once holds **if and only if the receiver deduplicates on
``idempotency_key``** — i.e. re-issuing an effect whose first attempt
actually landed must not apply it twice. The ledger re-issues under the
*same* idempotency key; the :class:`DedupReceiver` is the component that
makes the second issue a no-op. A production receiver must be durable
(database, Redis, a file) — :class:`InMemoryDedupReceiver` is for tests and
single-process use only.

Reconcile table (``run_tool`` on resume)
----------------------------------------
- ``completed`` + cached result        -> replay the result, zero re-execution
- ``completed`` + receiver query hit   -> return the receiver's result
- ``completed`` + result unrecoverable  -> fail closed (see below)
- ``started`` (no ``completed``) + receiver query hit
  -> adopt as completed (no re-execution of the raw effect)
- ``started`` (no ``completed``) + receiver query miss
  -> re-issue under the same idempotency key (the receiver dedups)
- ``started`` (no ``completed``) + no receiver
  -> fail closed: the effect is ambiguous and exactly-once is unprovable
- ``failed`` / never seen             -> fresh attempt

A ``completed`` tool call whose result exceeded the inline cap
(:data:`MAX_INLINE_RESULT_BYTES`) and has no receiver to ask is
*unrecoverable*: the event trail proves the effect happened exactly once,
but its result is gone, so resuming would have to re-run the raw effect and
risk double application. The ledger refuses loudly instead of guessing.
Deployments with large tool results must provide a receiver.

Crash sites
-----------
``run_tool`` calls ``crash_hook(site)`` — when set — at four sites per tool
call: ``before-tool-started:<id>``, ``after-tool-started:<id>``,
``before-tool-completed:<id>``, ``after-tool-completed:<id>``. The hook may
raise :class:`SimulatedCrash` (a ``BaseException``, like ``KeyboardInterrupt``)
to model ``kill -9``: unlike a real tool failure, a simulated crash writes
*no* ``tool.failed`` event, because a killed process writes nothing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable, Protocol

LEDGER_SCHEMA_VERSION = "northstar.tool-ledger.v1"
#: Canonical JSON results at or under this size are cached inline in the
#: sidecar for zero-re-execution replay. Larger results are digest-only and
#: require a DedupReceiver to replay (see the module docstring).
MAX_INLINE_RESULT_BYTES = 4096

_TOOL_CALL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_EVENT_KEY_RE = re.compile(r"^tool:([A-Za-z0-9_-]{1,128}):attempt-(\d+):(started|completed|failed)$")

_STARTED = "tool.started"
_COMPLETED = "tool.completed"
_FAILED = "tool.failed"


class SimulatedCrash(BaseException):
    """Deterministic stand-in for ``kill -9`` in crash-injection tests.

    A ``BaseException`` (not ``Exception``) so it propagates through the
    runner's ``except Exception`` failure-recording handler exactly like
    ``KeyboardInterrupt``: no ``step.failed`` / ``run.failed`` / ``tool.failed``
    markers are written, because a killed process writes nothing.
    """


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_tool_call_id(value: Any) -> str:
    if not isinstance(value, str) or not _TOOL_CALL_ID_RE.fullmatch(value):
        raise ValueError(
            "tool_call_id must be 1-128 chars of [A-Za-z0-9_-] (no colons: "
            "it is embedded in the event idempotency key)"
        )
    return value


def _require_idempotency_key(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("idempotency_key must be a non-empty string")
    if not re.fullmatch(r"[^\s/\\]+", value):
        raise ValueError("idempotency_key is invalid")
    return value


class DedupReceiver(Protocol):
    """Receiver-side idempotency for one tool effect.

    The ledger re-issues an ambiguous effect under the *same* idempotency
    key; the receiver makes the re-issue safe. ``query`` is the compensation
    path ("did this key's effect already happen?"); ``execute`` is the
    deduplicating execution path. Both must agree on the same backing store
    or exactly-once degrades to at-least-once.
    """

    def query(self, idempotency_key: str) -> tuple[bool, Any]:
        """Return ``(found, result)`` for a past execution of this key."""
        ...

    def execute(self, idempotency_key: str, fn: Callable[[], Any]) -> Any:
        """Run ``fn`` at most once per key; return the stored result on replay."""
        ...


class InMemoryDedupReceiver:
    """Dict-backed receiver. Single-process / tests only — not durable.

    A real deployment must back this with durable storage (database, Redis,
    a file); an in-memory dict does not survive the crash this ledger is
    built to recover from.
    """

    def __init__(self) -> None:
        self._results: dict[str, Any] = {}

    def query(self, idempotency_key: str) -> tuple[bool, Any]:
        _require_idempotency_key(idempotency_key)
        if idempotency_key in self._results:
            return True, self._results[idempotency_key]
        return False, None

    def execute(self, idempotency_key: str, fn: Callable[[], Any]) -> Any:
        _require_idempotency_key(idempotency_key)
        if idempotency_key in self._results:
            return self._results[idempotency_key]
        result = fn()
        self._results[idempotency_key] = result
        return result


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ValueError("tool ledger sidecar could not be persisted") from error


class ToolEffectLedger:
    """Per-tool-effect started/completed/failed ledger backed by the EventStore.

    ``append`` must accept the same keyword arguments as
    ``DurableRunner._append`` (``event_type``, ``status``, ``step_id``,
    ``idempotency_key``, ``now``, ``payload``) and persist one event; the
    runner binds its fencing ``owner_id``. ``crash_hook``, when set, is
    called with the site name before the hook's point of no return and may
    raise :class:`SimulatedCrash`.
    """

    def __init__(
        self,
        store: Any,
        *,
        run_id: str,
        ledger_path: str | Path,
        append: Callable[..., None],
        crash_hook: Callable[[str], None] | None = None,
    ):
        self._store = store
        self._run_id = run_id
        self._ledger_path = Path(ledger_path).absolute()
        self._append = append
        if crash_hook is not None and not callable(crash_hook):
            raise ValueError("crash_hook must be callable")
        self._crash_hook = crash_hook

    def _crash(self, site: str) -> None:
        if self._crash_hook is not None:
            self._crash_hook(site)

    def _tool_events(self, tool_call_id: str) -> list[Any]:
        prefix = f"tool:{tool_call_id}:"
        return [
            event
            for event in self._store.read_history(self._run_id)
            if event.event_type.startswith("tool.")
            and event.idempotency_key.startswith(prefix)
            and _EVENT_KEY_RE.fullmatch(event.idempotency_key) is not None
        ]

    def state_of(self, tool_call_id: str) -> str | None:
        """Last ledger state for this tool call: started/completed/failed/None."""
        _require_tool_call_id(tool_call_id)
        events = self._tool_events(tool_call_id)
        if not events:
            return None
        last = max(events, key=lambda event: event.sequence)
        return {
            _STARTED: "started",
            _COMPLETED: "completed",
            _FAILED: "failed",
        }[last.event_type]

    def _next_attempt(self, tool_call_id: str) -> int:
        return (
            sum(
                1
                for event in self._tool_events(tool_call_id)
                if event.event_type == _STARTED
            )
            + 1
        )

    def _read_sidecar(self) -> dict[str, Any]:
        if not self._ledger_path.exists():
            return {}
        try:
            value = json.loads(self._ledger_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("tool ledger sidecar is invalid") from error
        if not isinstance(value, dict) or value.get("schema_version") != LEDGER_SCHEMA_VERSION:
            raise ValueError("tool ledger sidecar has an unknown schema")
        results = value.get("results")
        if not isinstance(results, dict):
            raise ValueError("tool ledger sidecar results are invalid")
        return results

    def _cache_result(
        self, tool_call_id: str, idempotency_key: str, attempt: int, result: Any
    ) -> None:
        raw = _canonical_json(result)
        inline = raw if len(raw) <= MAX_INLINE_RESULT_BYTES else None
        results = self._read_sidecar()
        results[tool_call_id] = {
            "idempotency_key": idempotency_key,
            "attempt": attempt,
            "result_digest": _digest(result),
            "result": json.loads(inline.decode("utf-8")) if inline is not None else None,
            "result_inline": inline is not None,
        }
        _atomic_write_json(
            self._ledger_path,
            {
                "schema_version": LEDGER_SCHEMA_VERSION,
                "run_id": self._run_id,
                "results": results,
            },
        )

    def replay_result(self, tool_call_id: str) -> tuple[bool, Any]:
        """Return ``(found, result)`` for a completed tool call's cached result."""
        _require_tool_call_id(tool_call_id)
        entry = self._read_sidecar().get(tool_call_id)
        if entry is not None and entry.get("result_inline"):
            return True, entry["result"]
        return False, None

    def _append_ledger_event(
        self,
        *,
        phase: str,
        status: str,
        step_id: str,
        tool_call_id: str,
        attempt: int,
        now: int,
        payload: dict[str, Any],
    ) -> None:
        self._append(
            event_type=phase,
            status=status,
            step_id=step_id,
            idempotency_key=f"tool:{tool_call_id}:attempt-{attempt}:{phase.split('.')[1]}",
            now=now,
            payload={"tool_call_id": tool_call_id, "attempt": attempt, **payload},
        )

    def _adopt_completed(
        self,
        *,
        step_id: str,
        tool_call_id: str,
        idempotency_key: str,
        attempt: int,
        now: int,
        result: Any,
    ) -> None:
        # Compensation query proved the effect already happened: record the
        # adoption so the event trail converges, cache the adopted result,
        # and never re-execute the raw effect.
        self._append_ledger_event(
            phase=_COMPLETED,
            status="finished",
            step_id=step_id,
            tool_call_id=tool_call_id,
            attempt=attempt,
            now=now,
            payload={
                "idempotency_key": idempotency_key,
                "result_digest": _digest(result),
                "adopted": True,
            },
        )
        self._cache_result(tool_call_id, idempotency_key, attempt, result)

    def _execute_attempt(
        self,
        *,
        step_id: str,
        tool_call_id: str,
        idempotency_key: str,
        fn: Callable[[str], Any],
        now: int,
        attempt: int,
    ) -> Any:
        base_payload = {"idempotency_key": idempotency_key}
        self._crash(f"before-tool-started:{tool_call_id}")
        self._append_ledger_event(
            phase=_STARTED,
            status="running",
            step_id=step_id,
            tool_call_id=tool_call_id,
            attempt=attempt,
            now=now,
            payload=base_payload,
        )
        self._crash(f"after-tool-started:{tool_call_id}")
        try:
            # The raw effect receives the idempotency key for this attempt:
            # route it through receiver.execute(key, ...) inside fn so a
            # re-issued attempt is deduplicated by the receiver instead of
            # applied twice.
            result = fn(idempotency_key)
        except SimulatedCrash:
            # A killed process writes nothing: no tool.failed, exactly like
            # SIGKILL. The next reconcile sees started-without-completed.
            raise
        except BaseException as error:
            self._append_ledger_event(
                phase=_FAILED,
                status="failed",
                step_id=step_id,
                tool_call_id=tool_call_id,
                attempt=attempt,
                now=now,
                payload={**base_payload, "error_class": error.__class__.__name__},
            )
            raise
        self._crash(f"before-tool-completed:{tool_call_id}")
        self._append_ledger_event(
            phase=_COMPLETED,
            status="finished",
            step_id=step_id,
            tool_call_id=tool_call_id,
            attempt=attempt,
            now=now,
            payload={**base_payload, "result_digest": _digest(result)},
        )
        # The sidecar is a best-effort result cache, not the source of truth:
        # a crash between the event append and this write leaves a completed
        # event without a cached result, and reconcile falls back to the
        # receiver's dedup store (or fails closed if there is none).
        self._cache_result(tool_call_id, idempotency_key, attempt, result)
        self._crash(f"after-tool-completed:{tool_call_id}")
        return result

    def run_tool(
        self,
        *,
        step_id: str,
        tool_call_id: str,
        fn: Callable[[str], Any],
        now: int,
        idempotency_key: str | None = None,
        receiver: DedupReceiver | None = None,
    ) -> Any:
        """Execute one tool effect with ledger reconcile.

        See the module docstring for the reconcile table. ``fn`` receives the
        idempotency key for this attempt; when a receiver is in play the
        caller must route the raw effect through ``receiver.execute(key,
        ...)`` inside ``fn`` — that is what makes a re-issued attempt a
        no-op instead of a double application.
        """
        _require_tool_call_id(tool_call_id)
        if not callable(fn):
            raise ValueError("fn must be callable")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        key = (
            _require_idempotency_key(idempotency_key)
            if idempotency_key is not None
            else f"{self._run_id}:{step_id}:{tool_call_id}"
        )
        state = self.state_of(tool_call_id)
        attempt = self._next_attempt(tool_call_id)

        if state == "completed":
            found, result = self.replay_result(tool_call_id)
            if found:
                return result
            if receiver is not None:
                hit, result = receiver.query(key)
                if hit:
                    return result
            raise ValueError(
                "tool effect completed but its result is unrecoverable "
                "(exceeds the inline cap and no receiver holds it): refusing "
                "to re-run the raw effect and risk double application"
            )

        if state == "started":
            if receiver is None:
                raise ValueError(
                    "ambiguous tool effect (started, never completed) without "
                    "a DedupReceiver: provide one or make the tool idempotent"
                )
            hit, result = receiver.query(key)
            if hit:
                self._adopt_completed(
                    step_id=step_id,
                    tool_call_id=tool_call_id,
                    idempotency_key=key,
                    attempt=attempt,
                    now=now,
                    result=result,
                )
                return result
            return self._execute_attempt(
                step_id=step_id,
                tool_call_id=tool_call_id,
                idempotency_key=key,
                fn=fn,
                now=now,
                attempt=attempt,
            )

        # state is None (never seen) or "failed": fresh attempt.
        return self._execute_attempt(
            step_id=step_id,
            tool_call_id=tool_call_id,
            idempotency_key=key,
            fn=fn,
            now=now,
            attempt=attempt,
        )
