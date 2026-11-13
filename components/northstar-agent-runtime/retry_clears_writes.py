"""Retry clears writes: discard pending writes before re-invoking a retried node.

What was missing
----------------
Northstar's retry machinery decides *whether to try again* and *how long to
wait* (:mod:`retry_config`, :mod:`retry_contract`, :mod:`intent_bound_retry`).
None of it decides *what happens to the half-finished work of the attempt that
failed*.  A node that writes state and then fails leaves those writes behind.
If the retry runs with the old writes still in place, the effect is applied
twice: once by the attempt that failed, once by the attempt that succeeded.

LangGraph closes that hole in one line.  In
``libs/langgraph/langgraph/pregel/_retry.py`` the retry loop clears the
task's writes **before every attempt** (read 2026-11-14, main branch):

    while True:
        ...
        try:
            # clear any writes from previous attempts
            task.writes.clear()
            # run the task
            return task.proc.invoke(task.input, config)

The same clearing appears on the timeout path (``scope.close()``,
``task.writes.clear()``, ``bg.cancel()``) and in the async twin.  Writes are
the only outlet of a node's work, so clearing them is clearing the attempt.

The retry loop around it (same file) is the other half of the rule:

* a matching ``RetryPolicy`` is selected by ``_should_retry_on``; if no policy
  matches, the exception is raised as-is;
* ``attempts`` counts **failed attempts only**;
* ``attempts >= matching_policy.max_attempts`` gives up and re-raises;
* the wait is ``min(max_interval, initial_interval * backoff_factor **
  (attempts - 1))``, plus ``random.uniform(0, 1)`` when ``jitter`` is set;
* before the next attempt the config is marked as resuming.

``RetryPolicy``'s defaults (``libs/langgraph/langgraph/types.py``) are
``initial_interval=0.5``, ``backoff_factor=2.0``, ``max_interval=128.0``,
``max_attempts=3``, ``jitter=True``.

Cancellation has two shapes and they must not be confused (same file, async
path): a ``CancelledError`` raised by the *runtime* because a sibling failed
propagates untouched, while a ``CancelledError`` raised by the *node body* is
converted into a node-cancelled error, because otherwise the run would report
``success`` for a node that never finished.

Northstar extensions (not from LangGraph):

* **"Pending writes" are Northstar's writes.**  In LangGraph a write is a
  Pregel channel write held by the task.  Here a write is a node's write to
  the ledger / checkpoint layer: a key, a value and a write sequence number.
  The "clearing" therefore means *discard this attempt's uncommitted writes*;
  committed writes are not in the pending set and are never touched.
* **The write set is its own object** (:class:`PendingWrites`) rather than a
  field on the task, so the rule can be driven without a Pregel executor.
  :mod:`durable_resume` already models the same distinction from the other
  side (``put_writes`` / ``pending_writes``): a pending write is declared,
  not committed.
* **Committed writes live beside pending ones** so the acceptance test can
  show that clearing pending writes leaves the committed ones alone.
* **The timeout path** is driven with a worker thread, because a synchronous
  node cannot be interrupted.  The pending writes are cleared and the set is
  sealed so a late write from the abandoned worker cannot slip in.
* Only the "clear before a retry" rule is implemented.  LangGraph's whole
  Pregel executor, its checkpointing, its interrupt machinery and its
  streaming are **not** reimplemented here.

Version pin: retry-clears-writes.v1
Schema pin: northstar.retry-clears-writes.v1
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

#: Version pin for this module.
RETRY_CLEARS_WRITES_VERSION = "retry-clears-writes.v1"

#: Schema pin for the records this module produces.
SCHEMA_PIN = "northstar.retry-clears-writes.v1"

#: The channel a node writes its result to, mirroring LangGraph's ``RETURN``.
RETURN_CHANNEL = "__return__"

#: The config key LangGraph sets before a retry (``CONFIG_KEY_RESUMING``).
CONFIG_KEY_RESUMING = "__pregel_resuming"

#: The config section LangGraph patches (``CONF`` in ``langchain_core.runnables.config``).
CONF = "configurable"


class NodeCancelledError(Exception):
    """The node body itself was cancelled.

    Mirrors LangGraph's ``errors.NodeCancelledError``.  It exists so that a
    node which raised ``asyncio.CancelledError`` itself does not look like a
    successful run: the error takes the ordinary failure path (policy
    matching, attempts, give-up), and if no policy matches it is raised.
    """


class NodeTimeoutError(Exception):
    """The attempt exceeded its timeout.

    Mirrors LangGraph's ``errors.NodeTimeoutError`` in role only: the pending
    writes are cleared before the error is raised.
    """


class ExternalCancelledError(Exception):
    """The runtime cancelled the attempt because a sibling failed.

    Northstar extension (the shape LangGraph expresses with
    ``asyncio.Task.cancelling() >= 1``): an external cancellation propagates
    untouched and is never converted into a node failure.
    """


@dataclass(frozen=True)
class PendingWrite:
    """One uncommitted write: the key, the value, and the write sequence."""

    key: str
    value: Any
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {"key": self.key, "value": self.value, "seq": self.seq}


@dataclass
class PendingWrites:
    """The uncommitted writes of the current attempt, plus the committed ones.

    ``clear()`` drops every pending write.  It never touches the committed
    writes: a committed write is not in the pending set, so there is nothing
    for the clearing to take.
    """

    _writes: list[PendingWrite] = field(default_factory=list)
    _committed: list[PendingWrite] = field(default_factory=list)
    _seq: int = 0
    _sealed: bool = False

    def write(self, key: str, value: Any) -> bool:
        """Record an uncommitted write.  Returns False when the set is sealed."""
        if self._sealed:
            return False
        self._seq += 1
        self._writes.append(PendingWrite(key=str(key), value=value, seq=self._seq))
        return True

    def clear(self) -> int:
        """Discard every pending write.  Returns how many were discarded."""
        discarded = len(self._writes)
        self._writes = []
        return discarded

    def seal(self) -> None:
        """Refuse further writes (used after an abandoned attempt)."""
        self._sealed = True

    def commit(self, key: str | None = None) -> tuple[PendingWrite, ...]:
        """Move pending writes to the committed set.  Committed writes survive
        every later ``clear()``."""
        selected = [w for w in self._writes if key is None or w.key == key]
        if not selected:
            return ()
        self._writes = [w for w in self._writes if w not in selected]
        self._committed.extend(selected)
        return tuple(selected)

    def pending(self) -> tuple[PendingWrite, ...]:
        return tuple(self._writes)

    def committed(self) -> tuple[PendingWrite, ...]:
        return tuple(self._committed)

    def keys(self) -> tuple[str, ...]:
        return tuple(w.key for w in self._writes)

    def values(self) -> tuple[Any, ...]:
        return tuple(w.value for w in self._writes)

    def get(self, key: str, default: Any = None) -> Any:
        for write in reversed(self._writes):
            if write.key == key:
                return write.value
        return default

    def return_value(self) -> Any:
        """The value on the ``RETURN`` channel, if the node wrote one."""
        for write in reversed(self._writes):
            if write.key == RETURN_CHANNEL:
                return write.value
        return None

    def __len__(self) -> int:
        return len(self._writes)

    def __iter__(self):
        return iter(tuple(self._writes))


def default_retry_on(exc: Exception) -> bool:
    """LangGraph's default ``retry_on`` predicate (verbatim behaviour).

    Verbatim from ``libs/langgraph/langgraph/_internal/_retry.py`` (main
    branch, read 2026-11-14): ``ConnectionError`` retries; ``httpx`` and
    ``requests`` HTTP errors retry on a 5xx status; a fixed list of
    "programming error" exceptions never retries; everything else retries.

    The HTTP arms need ``httpx`` / ``requests``; when those are not
    installed the arms are skipped, exactly as LangGraph's own import inside
    the function body would skip them.
    """
    try:
        import httpx
    except ImportError:  # pragma: no cover - optional dependency
        httpx = None
    try:
        import requests
    except ImportError:  # pragma: no cover - optional dependency
        requests = None

    if isinstance(exc, ConnectionError):
        return True
    if httpx is not None and isinstance(exc, httpx.HTTPStatusError):
        return 500 <= exc.response.status_code < 600
    if requests is not None and isinstance(exc, requests.HTTPError):
        return 500 <= exc.response.status_code < 600 if exc.response else True
    if isinstance(
        exc,
        (
            ValueError,
            TypeError,
            ArithmeticError,
            ImportError,
            LookupError,
            NameError,
            SyntaxError,
            RuntimeError,
            ReferenceError,
            StopIteration,
            StopAsyncIteration,
            OSError,
        ),
    ):
        return False
    return True


@dataclass(frozen=True)
class RetryPolicy:
    """Retry configuration, with LangGraph's defaults.

    Verbatim from ``libs/langgraph/langgraph/types.py`` (main branch, read
    2026-11-14): ``initial_interval=0.5``, ``backoff_factor=2.0``,
    ``max_interval=128.0``, ``max_attempts=3``, ``jitter=True``.
    """

    initial_interval: float = 0.5
    backoff_factor: float = 2.0
    max_interval: float = 128.0
    max_attempts: int = 3
    jitter: bool = True
    retry_on: Any = default_retry_on

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int):
            raise ValueError("max_attempts must be an integer")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        for name in ("initial_interval", "backoff_factor", "max_interval"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a number")
        if self.initial_interval < 0:
            raise ValueError("initial_interval must be >= 0")
        if self.backoff_factor < 1.0:
            raise ValueError("backoff_factor must be >= 1.0")
        if self.max_interval < 0:
            raise ValueError("max_interval must be >= 0")

    def should_retry_on(self, exc: Exception) -> bool:
        """Does this policy match the exception?

        The three shapes are LangGraph's ``_should_retry_on`` (main branch,
        read 2026-11-14): a sequence of exception classes is matched with
        ``isinstance``; a single exception class is matched with
        ``isinstance`` too (LangGraph checks ``issubclass(retry_on,
        Exception)`` first and then uses ``isinstance``); a callable is called
        with the exception.  Anything else is a ``TypeError``.
        """
        retry_on = self.retry_on
        if isinstance(retry_on, Sequence):
            return isinstance(exc, tuple(retry_on))
        if isinstance(retry_on, type) and issubclass(retry_on, Exception):
            return isinstance(exc, retry_on)
        if callable(retry_on):
            return bool(retry_on(exc))
        raise TypeError(
            "retry_on must be an Exception class, a list or tuple of Exception classes, or a callable"
        )

    def interval(self, attempts: int) -> float:
        """The wait before the next attempt, without jitter.

        ``min(max_interval, initial_interval * backoff_factor ** (attempts - 1))``
        -- LangGraph's formula, with ``attempts`` counting failed attempts.
        """
        raw = self.initial_interval * (self.backoff_factor ** (attempts - 1))
        return min(self.max_interval, raw)


def _sleep_interval(policy: RetryPolicy, attempts: int, uniform: Callable[[float, float], float]) -> float:
    """The wait before the next attempt, with jitter when the policy asks.

    LangGraph: ``interval + random.uniform(0, 1)`` when ``jitter`` is set,
    otherwise the bare interval.  The uniform source is injectable so the
    boundary is testable.
    """
    interval = policy.interval(attempts)
    if policy.jitter:
        interval = interval + uniform(0.0, 1.0)
    return interval


@dataclass
class AttemptRecord:
    """What one attempt did, for the audit trail."""

    number: int
    resuming: bool
    cleared: int
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.number,
            "resuming": self.resuming,
            "cleared_writes": self.cleared,
            "error": self.error,
        }


@dataclass
class RetryOutcome:
    """The result of a retried node run."""

    value: Any = None
    attempts: int = 0
    resumed: bool = False
    writes: tuple[PendingWrite, ...] = ()
    records: tuple[AttemptRecord, ...] = ()
    config: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "attempts": self.attempts,
            "resumed": self.resumed,
            "writes": [w.as_dict() for w in self.writes],
            "records": [r.as_dict() for r in self.records],
            "config": self.config,
        }


def _match_policy(
    policies: Sequence[RetryPolicy], exc: BaseException
) -> RetryPolicy | None:
    """The first policy that matches the exception (LangGraph's selection).

    LangGraph walks the policy list and takes the first one whose
    ``retry_on`` matches; if none matches, the exception is raised unchanged.
    """
    for policy in policies:
        if isinstance(exc, Exception) and policy.should_retry_on(exc):
            return policy
    return None


def patch_configurable(config: dict[str, Any] | None, patch: dict[str, Any]) -> dict[str, Any]:
    """Patch the ``configurable`` section of a run config.

    Verbatim behaviour from ``langchain_core.runnables.config.patch_configurable``
    (read 2026-11-14): a missing config becomes ``{CONF: patch}``, a config
    without the section becomes ``{**config, CONF: patch}``, and otherwise the
    section is merged.
    """
    if config is None:
        return {CONF: dict(patch)}
    if CONF not in config:
        return {**config, CONF: dict(patch)}
    return {**config, CONF: {**config[CONF], **patch}}


def run_with_retry(
    node: Callable[[], Any],
    *,
    writes: PendingWrites,
    policies: Sequence[RetryPolicy] = (),
    timeout: float | None = None,
    sleep: Callable[[float], None] = time.sleep,
    uniform: Callable[[float, float], float] = random.uniform,
    resuming: bool = False,
    config: dict[str, Any] | None = None,
) -> RetryOutcome:
    """Run a node, clearing the pending writes before every attempt.

    The rule, in the order it is applied (LangGraph ``run_with_retry``, main
    branch, read 2026-11-14):

    1. **Before every attempt** the pending writes are cleared -- the first
       line of the ``try`` block.  A failed attempt's writes therefore never
       reach the next attempt, so a retried node cannot apply the same effect
       twice.
    2. The node runs.
    3. On failure the matching policy is selected; no match means the
       exception is raised as-is.
    4. ``attempts`` counts failed attempts only.
    5. ``attempts >= policy.max_attempts`` gives up and the exception is
       raised.
    6. Otherwise the loop waits
       ``min(max_interval, initial_interval * backoff_factor ** (attempts - 1))``
       (+ ``random.uniform(0, 1)`` with jitter), marks the run as resuming,
       and tries again.

    Cancellation is split two ways (LangGraph's async path): an
    :class:`ExternalCancelledError` propagates untouched, while an
    ``asyncio.CancelledError`` raised by the node body becomes a
    :class:`NodeCancelledError` and takes the ordinary failure path.

    On the timeout path the pending writes are cleared and the write set is
    sealed, so an abandoned worker cannot write into the next attempt.
    """
    policies = tuple(policies)
    attempts = 0
    records: list[AttemptRecord] = []
    was_resuming = False
    config = dict(config) if config is not None else {}

    while True:
        # The clearing rule: first line of the attempt (LangGraph
        # ``pregel/_retry.py`` line 635, read 2026-11-14).
        cleared = writes.clear()
        record = AttemptRecord(number=attempts + 1, resuming=was_resuming, cleared=cleared)
        records.append(record)
        try:
            if timeout is None:
                value = node()
            else:
                value = _run_with_timeout(node, writes, timeout)
        except ExternalCancelledError:
            # External cancellation propagates: the runtime already knows the
            # run is failing.
            record.error = "external-cancelled"
            writes.clear()
            raise
        except asyncio.CancelledError as exc:
            # The node body itself was cancelled.  Converting it keeps the run
            # from reporting success for a node that never finished.
            record.error = "node-cancelled"
            writes.clear()
            raise NodeCancelledError("node cancelled") from exc
        except BaseException as exc:
            record.error = type(exc).__name__
            policy = _match_policy(policies, exc)
            if policy is None:
                # No policy matches: the exception is raised unchanged, and
                # the failed attempt's writes are discarded rather than left
                # pending for someone else to commit.
                writes.clear()
                raise
            attempts += 1
            if attempts >= policy.max_attempts:
                # Out of attempts: the last exception is raised, and the
                # pending writes of the failed attempt stay cleared.
                writes.clear()
                raise
            delay = _sleep_interval(policy, attempts, uniform)
            sleep(delay)
            was_resuming = True
            resuming = True
            # Mark the run as resuming before the next attempt (LangGraph:
            # ``config = patch_configurable(config, {CONFIG_KEY_RESUMING: True})``).
            config = patch_configurable(config, {CONFIG_KEY_RESUMING: True})
            continue
        else:
            return RetryOutcome(
                value=value,
                attempts=attempts,
                resumed=resuming,
                writes=tuple(writes.pending()),
                records=tuple(records),
                config=config,
            )


def _run_with_timeout(node: Callable[[], Any], writes: PendingWrites, timeout: float) -> Any:
    """Run the node under a timeout, clearing the writes when it expires.

    LangGraph's timeout path clears the task's writes before raising
    ``NodeTimeoutError`` (main branch, read 2026-11-14).  A synchronous node
    cannot be interrupted, so the worker runs in a thread and the write set is
    sealed when the attempt is abandoned.
    """
    import threading

    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            box["value"] = node()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            box["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        # The attempt is abandoned: clear the writes and seal the set so a
        # late write from the abandoned worker cannot slip in.
        writes.clear()
        writes.seal()
        raise NodeTimeoutError("node timed out")
    if "error" in box:
        raise box["error"]
    return box.get("value")


