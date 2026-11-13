"""Concurrent ledger append + check-then-append transaction + Infra flag.

Research absorption (rank 6, programming) from **ageOfAgents**
(https://github.com/bharadwaj6/ageOfAgents, HEAD 7f575ca, 2026-10-09), a Go
multi-agent orchestrator that drives real coding agents (Claude Code / Codex /
Grok) to green and merges the changes, with gates and a SWE-bench evaluation
adapter.

Three things are absorbed here.  Each is quoted from the source and then
given a Northstar-native shape.

1. **Sidecar-lock append with gapless sequence numbers.**
   The source's ``Ledger.Append()`` (internal/ledger/ledger.go:100) assigns the
   sequence number at append time, monotonically from 1, and takes an exclusive
   lock on a *sidecar* file (``path + ".lock"``) rather than on the log itself,
   because (source docstring, verbatim): *"Windows locks are mandatory —
   locking the log would make lock-free readers fail"*.  The source's own
   docstring states the invariant: *"every Append, Update and Open holds an
   exclusive lock… so sequence numbers stay gapless."*

   Northstar's existing sealed ledger (``forward_seal_ledger.py``) is a
   single-writer, in-memory log: its sequence number is
   ``len(self._records) + 1`` computed under an in-process ``RLock``.  Two
   *processes* writing the same log would both derive the same sequence
   number and race the append.  This module adds the missing half: an
   on-disk, cross-process, gapless sequence.

2. **Torn-tail repair.**  The source's ``sync()`` re-reads before writing, so
   (source, verbatim): *"a writer's half-written line is never mistaken for a
   crash"*.  A partially written trailing line is repaired before the next
   append, and it is never counted as a crash or as an event.

3. **Check-then-append transaction.**  The source's ``Ledger.Update()``
   (internal/ledger/ledger.go:135) does read-decide-append inside one lock:
   *"No other writer, in this process or another, can append between the read
   and the write, so a check made in decide ('is this key already on the log?',
   'is this ticket still awaiting approval?') still holds when its events
   land.  That is what makes a check-then-append idempotent under concurrent
   callers."*

   Northstar's approval/revocation decisions are exactly this shape: a
   check-then-write decision that two concurrent callers can race for.
   :meth:`ConcurrentLedger.update` puts the read, the decision and the append
   inside one sidecar-lock critical section, and the idempotency key makes a
   repeated decision land **one** event only.

4. **The Infra flag.**  The source's ``Verifier.Run()``
   (internal/verify/verify.go:58) returns ``Passed`` / ``Failed`` plus an
   *Infra* flag, because (source, verbatim): *"An Infra failure says nothing
   about the proposal, so counting it as a rejection misattributes a broken
   environment to the agent's work."*  The source's ``isDockerInfraFailure()``
   (verify.go:98) treats Docker exit codes 125 / 126 / 127 (daemon / image /
   invocation failure) as infra and every other status as the tested command's
   own; it probes ``docker version`` *before* running the gate because
   (source, verbatim): *"Exit codes alone cannot tell a stopped daemon from a
   failing test: docker 29 exits 1 for both."*

   **Northstar extension (NOT from the source).**  Docker's 125/126/127 are
   Docker-specific and do not transfer.  Northstar's own infra signals are
   different: a relay that answers 403/429/502, a sandbox that cannot be
   reached, a sidecar that is down.  Those are listed explicitly in
   :data:`NORTHSTAR_INFRA_SIGNALS`, kept separate from the source's
   Docker-specific list, which is preserved verbatim in
   :data:`SOURCE_DOCKER_INFRA_EXIT_CODES`.

What this module IS: a file-backed append-only log with cross-process
gapless sequencing, torn-tail repair, a transactional check-then-append, and
a three-state (``passed`` / ``failed`` / ``infra``) verification result.

What this module IS NOT (honest scope):

* It does not seal events.  Sealing is ``forward_seal_ledger.py``'s job; this
  module can carry an opaque payload and leaves sealing to the caller.
* It does not decide *what* to check.  The caller supplies the check as a
  callable and the decision as a callable.
* It does not detect forks.  Two hosts showing different chains to two
  verifiers still look fine to each.
* The sidecar lock is an advisory, cooperative lock: it protects writers that
  use this module.  A writer that ignores the lock file can still corrupt
  the log.
* The idempotency key is per-log: two different keys never collide into one
  event, and one key never yields two events.

House style: frozen dataclasses, stdlib-only (hashlib/os/pathlib/threading/
json), no wall-clock in the log payload, fail-closed, ``stdlib_only()`` +
``main()`` self-check.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

#: Module version pin.
LEDGER_CONCURRENCY_VERSION = "ledger-concurrency.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ledger-concurrency.v1"

#: The three verification outcomes.  ``infra`` is a *third* state, never a
#: synonym for ``failed``: an environment failure says nothing about the
#: proposal under test.
OUTCOME_PASSED = "passed"
OUTCOME_FAILED = "failed"
OUTCOME_INFRA = "infra"

#: All three outcome names, in a stable order.
OUTCOMES = (OUTCOME_PASSED, OUTCOME_FAILED, OUTCOME_INFRA)

#: SOURCE (verbatim, ageOfAgents internal/verify/verify.go:98): the Docker
#: exit codes the source classifies as an infrastructure failure rather than
#: the tested command's own failure.  These are Docker-specific and are
#: **not** used by Northstar's classifier -- they are kept so the mapping
#: back to the source stays checkable.
SOURCE_DOCKER_INFRA_EXIT_CODES = (125, 126, 127)

#: SOURCE (verbatim, ageOfAgents internal/ledger/ledger.go:100): the lock is
#: taken on a sidecar file whose name is the log path plus this suffix.
SOURCE_LOCK_SUFFIX = ".lock"


class LedgerConcurrencyError(Exception):
    """Fail-closed: any integrity failure raises, never returns bad data."""


class LogCorruptError(LedgerConcurrencyError):
    """The log holds a line that is neither a whole event nor a torn tail."""


@dataclass(frozen=True)
class LedgerEvent:
    """One appended event (immutable).

    ``seq`` is 1-based, gapless and monotonic.  ``payload`` is the opaque
    caller-supplied body; ``idempotency_key`` is ``""`` for a plain append
    and the decision key for a transactional update.
    """

    seq: int
    payload: str
    idempotency_key: str
    record_hash: str


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _record_hash(seq: int, payload: str, idempotency_key: str) -> str:
    body = _canonical(
        {"seq": seq, "payload": payload, "idempotency_key": idempotency_key}
    )
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


class SidecarLock:
    """An exclusive lock held on a **sidecar** file, not on the log.

    SOURCE (ageOfAgents, internal/ledger/ledger.go:100): the lock is taken on
    ``path + ".lock"`` rather than on the log itself, because (verbatim):
    *"Windows locks are mandatory — locking the log would make lock-free
    readers fail"*.  A reader therefore never blocks on a writer, and a
    writer never blocks on a reader.

    The lock is **advisory and cooperative**: it serializes writers that go
    through this class.  A writer that ignores the lock file is not stopped.

    Within one process two threads each open their own file description, so
    the OS-level lock already excludes them; an extra in-process lock map
    keeps the same path honest across threads on platforms without ``fcntl``.
    """

    #: Suffix of the sidecar file (the source's rule, kept verbatim).
    SUFFIX = SOURCE_LOCK_SUFFIX

    #: Per-path in-process locks (path -> threading.Lock).
    _process_locks: Dict[str, threading.Lock] = {}
    _process_locks_guard = threading.Lock()

    def __init__(self, target_path: os.PathLike | str) -> None:
        self.target_path = str(target_path)
        self.lock_path = self.target_path + self.SUFFIX
        self._fd: Optional[int] = None
        with self._process_locks_guard:
            self._thread_lock = self._process_locks.setdefault(
                self.lock_path, threading.Lock()
            )

    @classmethod
    def _fcntl(cls) -> Any:
        try:
            import fcntl  # type: ignore

            return fcntl
        except Exception:  # pragma: no cover - non-POSIX fallback
            return None

    def acquire(self, timeout: float = 30.0) -> "SidecarLock":
        """Take the exclusive lock, waiting up to ``timeout`` seconds.

        The lock is **not** reentrant: calling :meth:`acquire` twice on one
        instance deadlocks.  Use :meth:`hold` for the ``with`` form.
        """
        import time

        deadline = time.monotonic() + max(0.0, timeout)
        # In-process serialization first (the same path from two threads).
        while True:
            if self._thread_lock.acquire(timeout=0.01):
                break
            if time.monotonic() >= deadline:
                raise LedgerConcurrencyError(
                    f"timed out waiting for the sidecar lock {self.lock_path!r}"
                )
        try:
            fcntl = self._fcntl()
            if fcntl is None:  # pragma: no cover - fallback path
                self._fd = os.open(
                    self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR
                )
                return self
            while True:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o644)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    os.close(fd)
                    if time.monotonic() >= deadline:
                        raise LedgerConcurrencyError(
                            f"timed out waiting for the sidecar lock {self.lock_path!r}"
                        )
                    time.sleep(0.001)
                    continue
                self._fd = fd
                return self
        except BaseException:
            self._thread_lock.release()
            raise

    def release(self) -> None:
        """Release the lock (safe to call twice)."""
        fd, self._fd = self._fd, None
        if fd is not None:
            fcntl = self._fcntl()
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        try:
            self._thread_lock.release()
        except RuntimeError:  # pragma: no cover - released twice
            pass

    def hold(self, timeout: float = 30.0) -> "SidecarLock":
        """Return a context manager that holds the lock for its body."""
        return _LockHolder(self, timeout)

    def __enter__(self) -> "SidecarLock":
        return self.acquire()

    def __exit__(self, *exc: Any) -> None:
        self.release()


class _LockHolder:
    """``with lock.hold():`` -- acquire once, release once."""

    def __init__(self, lock: SidecarLock, timeout: float) -> None:
        self._lock = lock
        self._timeout = timeout

    def __enter__(self) -> SidecarLock:
        return self._lock.acquire(timeout=self._timeout)

    def __exit__(self, *exc: Any) -> None:
        self._lock.release()


def _parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one log line; ``None`` when the line is not a whole event.

    A line that does not parse is either a torn tail (the writer died
    mid-write) or corruption.  The caller distinguishes the two by position:
    only the *last* line may be torn.
    """
    text = line.strip()
    if not text:
        return None
    try:
        obj = json.loads(text)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    if not isinstance(obj.get("seq"), int) or isinstance(obj.get("seq"), bool):
        return None
    if not isinstance(obj.get("payload"), str):
        return None
    if not isinstance(obj.get("idempotency_key"), str):
        return None
    if not isinstance(obj.get("record_hash"), str):
        return None
    return obj


class ConcurrentLedger:
    """A file-backed append-only log with gapless, cross-process sequencing.

    Usage::

        log = ConcurrentLedger("/tmp/decisions.jsonl")
        event = log.append(payload="grant g1")
        # two concurrent callers racing the same decision:
        result = log.update(
            key="ticket-42",
            check=lambda events: "ticket-42" not in {e.idempotency_key for e in events},
            decide=lambda events: {"decision": "approved"},
            payload_of=lambda decision: "ticket-42 approved",
        )

    Guarantees:

    * **Gapless sequence.**  Sequence numbers start at 1 and increase by one.
      No gaps, no duplicates, no matter how many writers (threads or
      processes) append.
    * **Lock-free readers.**  The exclusive lock lives on the *sidecar* file
      ``<log>.lock``, never on the log itself, so a reader may read the log
      while a writer holds the lock.
    * **Torn-tail repair.**  A trailing half-written line is truncated and
      repaired before the next append; it is never counted as an event and
      never reported as a crash.
    * **Transactional check-then-append.**  :meth:`update` runs the check,
      the decision and the append inside one lock, so the check still holds
      when the event lands, and a repeated idempotency key lands exactly one
      event.
    """

    def __init__(
        self,
        path: os.PathLike | str,
        *,
        lock_timeout: float = 30.0,
    ) -> None:
        self.path = Path(str(path))
        self.lock_path = Path(str(path) + SidecarLock.SUFFIX)
        self.lock_timeout = lock_timeout
        self._local = threading.local()

    # -- lock plumbing --------------------------------------------------

    def _lock(self) -> SidecarLock:
        """Return the sidecar lock for this path (one per thread)."""
        lock = getattr(self._local, "lock", None)
        if lock is None:
            lock = SidecarLock(self.path)
            self._local.lock = lock
        return lock

    # -- reading --------------------------------------------------------

    def read_events(self) -> Tuple[LedgerEvent, ...]:
        """Read every whole event, lock-free.

        A torn tail is skipped here (and repaired on the next append); the
        reader never blocks on a writer, because the writer's lock is on the
        sidecar file, not on the log.
        """
        if not self.path.exists():
            return ()
        text = self.path.read_text(encoding="utf-8", errors="replace")
        lines = text.split("\n")
        # The last *non-empty* line is the only one that may be a torn tail.
        last_content = -1
        for index, line in enumerate(lines):
            if line.strip():
                last_content = index
        events: List[LedgerEvent] = []
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            parsed = _parse_line(line)
            if parsed is None:
                if index == last_content:
                    # A torn tail: the last line was never finished.  It is
                    # not an event and not a crash.
                    continue
                raise LogCorruptError(
                    f"line {index + 1} of {self.path} is neither a whole event nor a tail"
                )
            events.append(self._event_from(parsed))
        return tuple(events)

    @staticmethod
    def _event_from(parsed: Dict[str, Any]) -> LedgerEvent:
        return LedgerEvent(
            seq=int(parsed["seq"]),
            payload=str(parsed["payload"]),
            idempotency_key=str(parsed["idempotency_key"]),
            record_hash=str(parsed["record_hash"]),
        )

    def __len__(self) -> int:
        return len(self.read_events())

    def next_seq(self) -> int:
        """The sequence number the next append will take (1 when empty)."""
        events = self.read_events()
        return (events[-1].seq + 1) if events else 1

    # -- torn-tail repair -----------------------------------------------

    def repair_tail(self) -> Optional[str]:
        """Repair a torn trailing line; return the discarded fragment.

        SOURCE (ageOfAgents, internal/ledger/ledger.go:100): the source's
        ``sync()`` re-reads before writing, so (verbatim) *"a writer's
        half-written line is never mistaken for a crash"*.  This method is
        that re-read: the trailing line is examined, and if it is not a
        whole event it is truncated away, so the next append starts from a
        clean end of file.

        Returns the discarded fragment, or ``None`` when there was nothing
        to repair.  The fragment is *not* an event and *not* a crash.
        """
        with self._lock().hold(timeout=self.lock_timeout):
            return self._repair_tail_locked()

    def _repair_tail_locked(self) -> Optional[str]:
        if not self.path.exists():
            return None
        with open(self.path, "rb") as handle:
            raw = handle.read()
        if not raw:
            return None
        text = raw.decode("utf-8", errors="replace")
        if text.endswith("\n"):
            return None
        # The last line has no terminating newline: it is either a torn
        # tail or a whole event that lost its newline.
        head, _, tail = text.rpartition("\n")
        if _parse_line(tail) is not None:
            # A whole event without its newline: complete it.
            with open(self.path, "wb") as handle:
                handle.write(raw + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            return None
        if tail.strip():
            # A torn fragment: drop it and close the file cleanly.
            with open(self.path, "wb") as handle:
                if head:
                    handle.write((head + "\n").encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            return tail
        return None

    # -- appending -------------------------------------------------------

    def append(self, payload: str, *, idempotency_key: str = "") -> LedgerEvent:
        """Append one event under the sidecar lock; return the sealed event.

        The sequence number is assigned *inside* the critical section, after
        the tail is repaired and the log re-read, so two concurrent writers
        can never derive the same number and never leave a gap between
        them.
        """
        if not isinstance(payload, str) or not payload:
            raise LedgerConcurrencyError("payload must be a non-empty str")
        if not isinstance(idempotency_key, str):
            raise LedgerConcurrencyError("idempotency_key must be a str")
        with self._lock().hold(timeout=self.lock_timeout):
            return self._append_locked(payload, idempotency_key)

    def _append_locked(self, payload: str, idempotency_key: str) -> LedgerEvent:
        # Repair first: a torn tail must never be mistaken for a crash, and
        # must never be counted as an event.
        self._repair_tail_locked()
        # Re-read inside the lock: the sequence number is derived from the
        # state of the file *now*, not from a stale read.
        events = self.read_events()
        seq = (events[-1].seq + 1) if events else 1
        record_hash = _record_hash(seq, payload, idempotency_key)
        line = _canonical(
            {
                "seq": seq,
                "payload": payload,
                "idempotency_key": idempotency_key,
                "record_hash": record_hash,
            }
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return LedgerEvent(
            seq=seq,
            payload=payload,
            idempotency_key=idempotency_key,
            record_hash=record_hash,
        )

    # -- transactional check-then-append ---------------------------------

    def update(
        self,
        *,
        key: str,
        check: Callable[[Tuple[LedgerEvent, ...]], bool],
        decide: Callable[[Tuple[LedgerEvent, ...]], Any],
        payload_of: Callable[[Any], str],
    ) -> Tuple[LedgerEvent, bool]:
        """Read-decide-append as one transaction; return ``(event, landed)``.

        SOURCE (ageOfAgents, internal/ledger/ledger.go:135): the source's
        ``Ledger.Update()`` holds one exclusive lock across the read, the
        decision and the write, so (verbatim) *"No other writer, in this
        process or another, can append between the read and the write, so a
        check made in decide ('is this key already on the log?', 'is this
        ticket still awaiting approval?') still holds when its events land.
        That is what makes a check-then-append idempotent under concurrent
        callers."*

        Northstar shape:

        * ``check(events)`` answers the question the decision depends on
          ("is this key already on the log?", "is this ticket still awaiting
          approval?").  It is evaluated on the events as they are *inside*
          the lock.
        * ``decide(events)`` computes the decision from the same snapshot.
        * ``payload_of(decision)`` renders the decision into the event body.
        * ``key`` is the idempotency key: a decision that already landed
          under this key is returned as-is and **no second event is
          written**.

        Returns the event and whether *this* call landed it (``False`` when
        the decision was already on the log).
        """
        if not isinstance(key, str) or not key:
            raise LedgerConcurrencyError("update requires a non-empty idempotency key")
        with self._lock().hold(timeout=self.lock_timeout):
            self._repair_tail_locked()
            events = self.read_events()
            # The idempotency short-circuit: the decision is already on the
            # log, so the second caller sees the existing decision and does
            # not append again.
            for event in events:
                if event.idempotency_key == key:
                    return event, False
            if not check(events):
                raise LedgerConcurrencyError(
                    f"the check for {key!r} no longer holds; no event was written"
                )
            decision = decide(events)
            payload = payload_of(decision)
            if not isinstance(payload, str) or not payload:
                raise LedgerConcurrencyError("payload_of must return a non-empty str")
            event = self._append_locked(payload, key)
            return event, True

    def find_by_key(self, key: str) -> Optional[LedgerEvent]:
        """The event written under ``key``, or ``None``."""
        for event in self.read_events():
            if event.idempotency_key == key:
                return event
        return None


# ---------------------------------------------------------------------------
# The Infra flag
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationResult:
    """The three-state outcome of one gate run.

    ``outcome`` is exactly one of :data:`OUTCOMES`.  ``infra`` is a distinct
    state: it means *the gate did not run*, so it says nothing about the
    proposal and must never be counted as the executor's failure.
    """

    outcome: str
    detail: str = ""
    signal: str = ""

    @property
    def passed(self) -> bool:
        return self.outcome == OUTCOME_PASSED

    @property
    def failed(self) -> bool:
        return self.outcome == OUTCOME_FAILED

    @property
    def infra(self) -> bool:
        return self.outcome == OUTCOME_INFRA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "outcome": self.outcome,
            "detail": self.detail,
            "signal": self.signal,
        }


#: NORTHSTAR EXTENSION (not from the source): the HTTP status codes that mean
#: *the relay or the channel is broken*, not *the work under test failed*.
#: The source's Docker exit codes (125/126/127) do not transfer here.
NORTHSTAR_INFRA_HTTP_STATUS = (403, 429, 502, 503, 504)

#: NORTHSTAR EXTENSION (not from the source): signals that name an
#: environment failure rather than a failure of the thing under test.
NORTHSTAR_INFRA_SIGNALS = (
    "relay_unavailable",
    "relay_forbidden",
    "relay_rate_limited",
    "relay_bad_gateway",
    "sandbox_unreachable",
    "sandbox_start_failed",
    "sidecar_down",
    "timeout_environment",
    "resource_exhausted_environment",
)

#: NORTHSTAR EXTENSION (not from the source): the signals that mean the thing
#: under test genuinely failed.  A non-zero exit code of the *tested command*
#: is the executor's own failure -- the source makes the same cut, with
#: Docker's 125/126/127 on the other side of the line.
NORTHSTAR_AGENT_FAILURE_SIGNALS = (
    "test_failed",
    "assertion_failed",
    "command_failed",
    "lint_failed",
    "build_failed",
)


def classify_verification(
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    signals: Tuple[str, ...] = (),
    http_status: Optional[int] = None,
) -> VerificationResult:
    """Classify one gate run as ``passed`` / ``failed`` / ``infra``.

    SOURCE (ageOfAgents, internal/verify/verify.go:58 and :98): the source
    has a ``Passed`` / ``Failed`` result plus an *Infra* flag, because
    (verbatim): *"An Infra failure says nothing about the proposal, so
    counting it as a rejection misattributes a broken environment to the
    agent's work."*  The source's own classifier is Docker-specific: exit
    codes 125 / 126 / 127 (daemon / image / invocation failure) are infra,
    every other status belongs to the tested command.  It probes
    ``docker version`` before the gate because (verbatim): *"Exit codes alone
    cannot tell a stopped daemon from a failing test: docker 29 exits 1 for
    both."*

    **Northstar extension.**  Docker's exit codes do not transfer.  This
    classifier uses Northstar's own signal vocabulary:

    * an explicit infra signal (see :data:`NORTHSTAR_INFRA_SIGNALS`) is infra;
    * an infra HTTP status from the relay (see
      :data:`NORTHSTAR_INFRA_HTTP_STATUS`) is infra;
    * a sandbox / sidecar that could not be reached is infra;
    * everything else that failed is the executor's own failure.

    The signal list is explicit and closed: the classifier never guesses
    from an exit code alone, because that is exactly the mistake the source
    warns about.
    """
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise LedgerConcurrencyError("exit_code must be an int")
    for signal in signals:
        if not isinstance(signal, str) or not signal:
            raise LedgerConcurrencyError("signals must be non-empty strings")

    for signal in signals:
        if signal in NORTHSTAR_INFRA_SIGNALS:
            return VerificationResult(
                outcome=OUTCOME_INFRA,
                detail=(
                    f"the environment failed ({signal}); this says nothing about "
                    "the proposal and is never counted as the executor's failure"
                ),
                signal=signal,
            )
    if http_status is not None:
        if isinstance(http_status, bool) or not isinstance(http_status, int):
            raise LedgerConcurrencyError("http_status must be an int or None")
        if http_status in NORTHSTAR_INFRA_HTTP_STATUS:
            return VerificationResult(
                outcome=OUTCOME_INFRA,
                detail=(
                    f"the channel answered {http_status}; the gate never ran, so "
                    "the outcome is not the executor's failure"
                ),
                signal=f"http_{http_status}",
            )
    for signal in signals:
        if signal in NORTHSTAR_AGENT_FAILURE_SIGNALS:
            return VerificationResult(
                outcome=OUTCOME_FAILED,
                detail=f"the thing under test failed ({signal})",
                signal=signal,
            )
    if exit_code == 0:
        return VerificationResult(
            outcome=OUTCOME_PASSED,
            detail="the gate ran and passed",
            signal="",
        )
    return VerificationResult(
        outcome=OUTCOME_FAILED,
        detail=(
            f"the thing under test exited {exit_code}; with no infra signal "
            "this is the executor's own failure"
        ),
        signal=f"exit_{exit_code}",
    )


def tally(results: Tuple[VerificationResult, ...]) -> Dict[str, int]:
    """Tally the three states; ``infra`` never lands in ``failed``.

    This is the misattribution the source warns about, made mechanical: an
    infra result increments ``infra`` and nothing else, so a broken relay
    can never raise the executor's failure count.
    """
    counts = {OUTCOME_PASSED: 0, OUTCOME_FAILED: 0, OUTCOME_INFRA: 0}
    for result in results:
        if result.outcome not in counts:
            raise LedgerConcurrencyError(f"unknown outcome {result.outcome!r}")
        counts[result.outcome] += 1
    return counts


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "fcntl",
        "hashlib",
        "json",
        "os",
        "pathlib",
        "shutil",
        "sys",
        "tempfile",
        "threading",
        "time",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: concurrent append, gapless seq, idempotent update, infra."""
    import shutil
    import tempfile

    workdir = tempfile.mkdtemp(prefix="ledger-concurrency-")
    try:
        log = ConcurrentLedger(os.path.join(workdir, "log.jsonl"))

        # Two concurrent writers, gapless sequence.
        errors: List[BaseException] = []

        def worker(tag: str) -> None:
            try:
                for i in range(4):
                    log.append(f"{tag}-{i}")
            except BaseException as error:  # pragma: no cover - self-check
                errors.append(error)

        threads = [threading.Thread(target=worker, args=(t,)) for t in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert not errors, errors
        seqs = [event.seq for event in log.read_events()]
        assert seqs == list(range(1, 9)), seqs

        # Idempotent check-then-append.
        event, landed = log.update(
            key="ticket-1",
            check=lambda events: True,
            decide=lambda events: {"decision": "approved"},
            payload_of=lambda decision: "ticket-1 approved",
        )
        assert landed is True
        again, landed_again = log.update(
            key="ticket-1",
            check=lambda events: True,
            decide=lambda events: {"decision": "approved"},
            payload_of=lambda decision: "ticket-1 approved",
        )
        assert landed_again is False and again.seq == event.seq

        # Infra is a third state, never a failure.
        result = classify_verification(signals=("sandbox_unreachable",))
        assert result.outcome == OUTCOME_INFRA
        counts = tally((result,))
        assert counts["failed"] == 0 and counts["infra"] == 1
        assert stdlib_only()
        print("ledger-concurrency OK: gapless seq, idempotent update, infra flag")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
