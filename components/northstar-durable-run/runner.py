"""A small local durable runner for the Northstar vertical slice.

This runner intentionally executes only caller-registered Python step functions
inside the test fixture. It is not a sandbox, scheduler, or production worker.
Its purpose is to prove lifecycle, lease, checkpoint, resume, cancellation, and
idempotent step boundaries before adding broader execution surfaces.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from blob_store import CLAIM_CHECK_THRESHOLD_BYTES
from durable_contract import (
    EVENT_SCHEMA_VERSION,
    RunContract,
    assert_transition,
    can_transition,
)
from event_store import EventStore
from tool_ledger import SimulatedCrash, ToolEffectLedger  # noqa: F401 - re-exported

if TYPE_CHECKING:
    from durable_audit import DurableEvidenceSink

try:  # POSIX only; without it the claim is thread-serial, not process-serial
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore[assignment]

_ID_RE = re.compile(r"^[^\s/\\]+$")
_SCOPE_RE = re.compile(r"^[^\s/\\:]+:[^\s/\\:]+$")
_MAX_INPUT_BYTES = 256_000
_PRIVATE_MODE = 0o700


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("step input must be JSON serializable") from error


def _digest(value: Any) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError(f"{field} is invalid")
    if not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _require_scopes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("scope_snapshot must be a list")
    if len(value) > 64:
        raise ValueError("scope_snapshot has too many entries")
    result: list[str] = []
    seen: set[str] = set()
    for scope in value:
        if not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope):
            raise ValueError("scope_snapshot contains an invalid scope")
        if scope in seen:
            raise ValueError("scope_snapshot contains a duplicate scope")
        seen.add(scope)
        result.append(scope)
    return tuple(result)


def _require_postconditions(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("expected_postconditions must be a list")
    result: list[str] = []
    seen: set[str] = set()
    for name in value:
        normalized = _require_id(name, "expected_postcondition")
        if normalized in seen:
            raise ValueError("expected_postconditions contains a duplicate")
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)


class FencingError(ValueError):
    """The execution lease's fencing epoch is over for this holder.

    Raised when a lease holder presents a stale fencing token: the lease was
    taken over by another owner, so this holder must stop writing instead of
    interleaving its events with the new holder's stream. A subclass of
    :class:`ValueError` so existing ``except ValueError`` guards keep working.
    """


def _require_fencing_token(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("lease fencing_token is invalid")
    return value


class _LeaseFileLock:
    """Serialize one lease file's read-modify-write on this host.

    The lock file (``<lease path>.lock``) is opened — never renamed and never
    deleted. Deleting or renaming it would reopen the inode-replacement race
    the lock exists to close: two processes could then hold locks on different
    inodes while believing they serialize the same lease. The lock file is
    never written, so there is nothing to corrupt; if a holder crashes, the
    kernel releases its ``flock`` and the next contender proceeds.

    Two layers, held only for the duration of the critical section (never
    across an action, a heartbeat interval, or any caller code):

    - ``threading.Lock``: always held — serializes threads of this process.
    - ``fcntl.flock(LOCK_EX)``: held only where ``fcntl`` exists (POSIX) —
      serializes cooperating processes on the same host. Where ``fcntl`` is
      unavailable the claim degrades honestly to thread-serial; see
      :meth:`LeaseManager.cross_process_serialized`.
    """

    def __init__(self, lease_path: Path):
        self._lock_path = Path(str(lease_path) + ".lock")
        self._thread_lock = threading.Lock()
        self._fd: int | None = None

    def __enter__(self) -> "_LeaseFileLock":
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._thread_lock.acquire()
        try:
            self._fd = os.open(str(self._lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            self._thread_lock.release()
            raise
        if fcntl is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX)
            except OSError:
                os.close(self._fd)
                self._fd = None
                self._thread_lock.release()
                raise
        return self

    def __exit__(self, *exc: Any) -> bool:
        try:
            if fcntl is not None and self._fd is not None:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
            self._thread_lock.release()
        return False


@dataclass(frozen=True)
class StepPlan:
    step_id: str
    input_payload: dict[str, Any]
    scope_snapshot: tuple[str, ...] | list[str]
    expected_postconditions: tuple[str, ...] | list[str]
    action: Callable[[str], dict[str, Any]]

    def __post_init__(self) -> None:
        _require_id(self.step_id, "step_id")
        if not isinstance(self.input_payload, dict):
            raise ValueError("input_payload must be an object")
        if len(_canonical_json(self.input_payload)) > _MAX_INPUT_BYTES:
            raise ValueError("step input exceeds the maximum size")
        object.__setattr__(self, "scope_snapshot", _require_scopes(self.scope_snapshot))
        object.__setattr__(
            self,
            "expected_postconditions",
            _require_postconditions(self.expected_postconditions),
        )
        if not callable(self.action):
            raise ValueError("step action must be callable")

    @property
    def input_digest(self) -> str:
        return _digest(self.input_payload)


class LeaseManager:
    """A single-owner, expiring local lease with fencing tokens.

    The lease file is strict JSON ``{"owner_id", "expires_at",
    "fencing_token"}``. Every successful :meth:`acquire` starts a new fencing
    epoch with a monotonically increasing token, so a holder from an older
    epoch is distinguishable from the current holder even after its TTL has
    lapsed. Heartbeats, renewals, and fenced appends must present the token of
    the epoch they belong to; a mismatch fails closed with :class:`FencingError`.

    Claim atomicity (what "one winner" means here)
    ---------------------------------------------
    The read-modify-write of :meth:`acquire`, :meth:`heartbeat`, :meth:`renew`,
    and :meth:`release` runs inside :class:`_LeaseFileLock`, so on one host:

    - POSIX (``fcntl`` available): cooperating processes are serialized — two
      processes racing an expired lease produce exactly one winner, and the
      fencing token increments exactly once per acquire.
    - without ``fcntl``: only threads of this process are serialized;
      cross-process atomicity is **unproven** (see
      :meth:`cross_process_serialized`).
    - across hosts: never — the lease is a local file; there is no
      distributed claim here.

    The lock and the fencing token are orthogonal: the lock decides *who got
    there first* (claim arbitration); the token decides *whose writes are
    still valid* (stale-holder detection). Neither replaces the other.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()
        self._file_lock = _LeaseFileLock(self.path)

    @property
    def cross_process_serialized(self) -> bool:
        """Whether mutating lease operations are serialized across processes.

        True on POSIX (``fcntl.flock`` on the ``<lease>.lock`` file). False
        where ``fcntl`` is unavailable: the critical sections are then only
        serialized across threads of this process, and two processes racing a
        claim can still both believe they won. Never silently stronger than
        this — check it before relying on the claim across processes.
        """
        return fcntl is not None

    def _read(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("lease file is invalid") from error
        if not isinstance(value, dict) or set(value) != {
            "owner_id",
            "expires_at",
            "fencing_token",
        }:
            raise ValueError("lease file has unknown or missing fields")
        _require_id(value.get("owner_id"), "lease owner_id")
        expires_at = value.get("expires_at")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0:
            raise ValueError("lease expires_at is invalid")
        _require_fencing_token(value.get("fencing_token"))
        return value

    def _write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            prefix=self.path.name + ".", dir=str(self.path.parent)
        )
        try:
            os.fchmod(fd, _PRIVATE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as error:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise ValueError("lease could not be persisted") from error

    def acquire(self, owner_id: str, *, now: int, ttl_seconds: int) -> dict[str, Any]:
        _require_id(owner_id, "owner_id")
        if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
            raise ValueError("now must be a positive integer")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        with self._file_lock:
            current = self._read()
            if current is not None and now < current["expires_at"]:
                raise ValueError("lease is held by another active owner")
            # A new fencing epoch on every acquire: the token only moves forward
            # per lease file, so an older epoch's holder can never present a
            # token that matches the current one. The file lock makes the
            # read-increment-write atomic across cooperating processes.
            token = current["fencing_token"] + 1 if current is not None else 1
            lease = {
                "owner_id": owner_id,
                "expires_at": now + ttl_seconds,
                "fencing_token": token,
            }
            self._write(lease)
            return lease

    def assert_valid(self, owner_id: str, *, now: int) -> dict[str, Any]:
        _require_id(owner_id, "owner_id")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        current = self._read()
        if current is None:
            raise ValueError("lease does not exist")
        if current["owner_id"] != owner_id:
            raise ValueError("lease owner does not match")
        if now >= current["expires_at"]:
            raise ValueError("lease has expired")
        return current

    def heartbeat(
        self, owner_id: str, *, token: int, now: int, ttl_seconds: int
    ) -> dict[str, Any]:
        _require_id(owner_id, "owner_id")
        _require_fencing_token(token)
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        with self._file_lock:
            current = self._read()
            if current is None:
                raise ValueError("lease does not exist")
            if current["owner_id"] != owner_id:
                raise FencingError("lease owner does not match")
            if now >= current["expires_at"]:
                raise ValueError("lease has expired")
            if current["fencing_token"] != token:
                raise FencingError(
                    "fencing token mismatch: the lease was taken over by another owner"
                )
            lease = {
                "owner_id": owner_id,
                "expires_at": now + ttl_seconds,
                "fencing_token": token,
            }
            self._write(lease)
            return lease

    def renew(
        self, owner_id: str, *, token: int, now: int, ttl_seconds: int
    ) -> dict[str, Any]:
        """Renew the lease from inside a still-running action.

        Unlike :meth:`heartbeat`, an expiry here does not abort: the caller is
        demonstrably alive (it is executing right now), so a cleanly expired
        lease is re-acquired into a new fencing epoch instead of being
        refused. A token mismatch still fails closed — someone else owns the
        lease now, and this holder is fenced.
        """
        _require_id(owner_id, "owner_id")
        _require_fencing_token(token)
        if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
            raise ValueError("now must be a positive integer")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        with self._file_lock:
            current = self._read()
            if current is None:
                raise FencingError("lease does not exist")
            if current["owner_id"] != owner_id or current["fencing_token"] != token:
                raise FencingError(
                    "fencing token mismatch: the lease was taken over by another owner"
                )
            new_token = token + 1 if now >= current["expires_at"] else token
            lease = {
                "owner_id": owner_id,
                "expires_at": now + ttl_seconds,
                "fencing_token": new_token,
            }
            self._write(lease)
            return lease

    def check_token(self, owner_id: str, *, token: int) -> dict[str, Any]:
        """Fail closed unless this owner still holds the current fencing epoch.

        Deliberately time-agnostic: an expired-but-untaken lease has no rival
        writer, so expiry alone is not a fence. A token mismatch (or a missing
        lease file) means the epoch is over — writes must stop.
        """
        _require_id(owner_id, "owner_id")
        _require_fencing_token(token)
        current = self._read()
        if current is None:
            raise FencingError("lease does not exist")
        if current["owner_id"] != owner_id:
            raise FencingError("lease owner does not match")
        if current["fencing_token"] != token:
            raise FencingError(
                "fencing token mismatch: the lease was taken over by another owner"
            )
        return current

    def release(self, owner_id: str) -> None:
        with self._file_lock:
            current = self._read()
            if current is None:
                return
            if current["owner_id"] != owner_id:
                raise ValueError("lease owner does not match")
            try:
                self.path.unlink()
            except FileNotFoundError:
                return
            except OSError as error:
                raise ValueError("lease could not be released") from error


class RunSupervisor:
    """Orchestrator-side execution-lease holder for one durable run.

    Diagrid pattern: the supervisor — not the worker process — owns the
    execution lease. It acquires the lease and heartbeats it while the worker
    is alive. The worker adopts the lease (see
    ``DurableRunner(adopt_lease=...)``): it fence-checks instead of
    heartbeating and never releases.

    If the worker dies, the supervisor stops heartbeating and the lease
    expires on its own. A healthy worker can then acquire the expired lease
    (a new fencing epoch, recorded as a state-neutral ``run.fenced`` marker)
    and resume from the EventStore — finished steps are skipped, a step that
    was started but never finished is re-run under the same action key.

    The lease is a local file, so supervision is single-host by design;
    cross-host orchestration is out of scope (see the component README).
    """

    def __init__(
        self,
        lease_path: str | Path,
        *,
        lease_ttl_seconds: int = 60,
        clock: Callable[[], int] | None = None,
    ):
        if not isinstance(lease_ttl_seconds, int) or isinstance(lease_ttl_seconds, bool) or lease_ttl_seconds <= 0:
            raise ValueError("lease_ttl_seconds must be a positive integer")
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self.lease = LeaseManager(lease_path)
        self.lease_ttl_seconds = lease_ttl_seconds
        self._clock = clock if clock is not None else lambda: int(time.time())

    def acquire(self, *, owner_id: str, now: int) -> dict[str, Any]:
        """Acquire the supervision lease. Returns the lease record (with token)."""
        return self.lease.acquire(owner_id, now=now, ttl_seconds=self.lease_ttl_seconds)

    def heartbeat(self, *, owner_id: str, token: int, now: int) -> dict[str, Any]:
        """Renew the supervision lease inside its fencing epoch."""
        return self.lease.heartbeat(
            owner_id, token=token, now=now, ttl_seconds=self.lease_ttl_seconds
        )

    def start_heartbeat(
        self, *, owner_id: str, token: int, interval_seconds: float = 1.0
    ) -> Callable[[], None]:
        """Heartbeat in a daemon thread until the returned ``stop()`` is called.

        ``interval_seconds`` must be well under ``lease_ttl_seconds``. A
        heartbeat failure (takeover, corruption) stops the loop and is
        re-raised by ``stop()`` — a supervisor that lost its lease must not
        keep pretending to supervise.
        """
        if not isinstance(interval_seconds, (int, float)) or interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if interval_seconds >= self.lease_ttl_seconds:
            raise ValueError("interval_seconds must be shorter than lease_ttl_seconds")
        stop = threading.Event()
        failures: list[BaseException] = []

        def _loop() -> None:
            while not stop.wait(interval_seconds):
                try:
                    now = self._clock()
                    if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
                        raise ValueError("clock must return a positive integer")
                    self.heartbeat(owner_id=owner_id, token=token, now=now)
                except BaseException as error:  # noqa: BLE001 - surfaced by stop()
                    failures.append(error)
                    return

        thread = threading.Thread(
            target=_loop, daemon=True, name="northstar-supervisor-heartbeat"
        )
        thread.start()

        def _stop() -> None:
            stop.set()
            thread.join(timeout=interval_seconds + 5)
            if failures:
                raise failures[0]

        return _stop

    def supervise(
        self,
        *,
        owner_id: str,
        now: int,
        spawn_worker: Callable[[str, int], Any],
        heartbeat_interval_seconds: float = 1.0,
        poll_interval_seconds: float = 0.05,
    ) -> str:
        """Run one supervision cycle: acquire, heartbeat, watch, report.

        ``spawn_worker(owner_id, token)`` must start and return a process-like
        object with ``is_alive()``, ``join(timeout)`` and ``exitcode`` (e.g.
        ``multiprocessing.Process``). Returns ``"completed"`` when the worker
        exits 0, ``"worker-died"`` otherwise. On worker death the heartbeat
        stops, so the lease expires and a later worker can take over via the
        normal expired-lease acquire path.
        """
        lease = self.acquire(owner_id=owner_id, now=now)
        token = lease["fencing_token"]
        stop = self.start_heartbeat(
            owner_id=owner_id, token=token, interval_seconds=heartbeat_interval_seconds
        )
        proc = spawn_worker(owner_id, token)
        try:
            while proc.is_alive():
                proc.join(timeout=poll_interval_seconds)
            return "completed" if proc.exitcode == 0 else "worker-died"
        finally:
            stop()


class DurableRunner:
    """Execute planned local steps with durable event and lease boundaries."""

    def __init__(
        self,
        run: RunContract,
        store: EventStore,
        *,
        lease_path: str | Path,
        lease_ttl_seconds: int = 60,
        clock: Callable[[], int] | None = None,
        heartbeat_interval_seconds: int | None = None,
        adopt_lease: tuple[str, int] | None = None,
        crash_hook: Callable[[str], None] | None = None,
        ledger_path: str | Path | None = None,
        evidence_sink: DurableEvidenceSink | None = None,
    ):
        if not isinstance(run, RunContract):
            raise ValueError("run must be a RunContract")
        if not isinstance(lease_ttl_seconds, int) or isinstance(lease_ttl_seconds, bool) or lease_ttl_seconds <= 0:
            raise ValueError("lease_ttl_seconds must be a positive integer")
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        if heartbeat_interval_seconds is not None:
            if (
                not isinstance(heartbeat_interval_seconds, int)
                or isinstance(heartbeat_interval_seconds, bool)
                or heartbeat_interval_seconds <= 0
            ):
                raise ValueError("heartbeat_interval_seconds must be a positive integer")
            if clock is None:
                raise ValueError("heartbeat_interval_seconds requires a clock")
            if heartbeat_interval_seconds >= lease_ttl_seconds:
                raise ValueError(
                    "heartbeat_interval_seconds must be shorter than lease_ttl_seconds"
                )
        self.run = run
        self.store = store
        if evidence_sink is not None:
            from durable_audit import DurableEvidenceSink

            if not isinstance(evidence_sink, DurableEvidenceSink):
                raise ValueError("evidence_sink must be a DurableEvidenceSink")
            if evidence_sink.run_id != run.run_id:
                raise ValueError("evidence_sink run_id does not match runner run")
            if evidence_sink.artifact_store is not store.blob_store:
                raise ValueError("evidence_sink must reference this EventStore's BlobStore")
        self.evidence_sink = evidence_sink
        self.lease = LeaseManager(lease_path)
        self.lease_ttl_seconds = lease_ttl_seconds
        # Adopted lease (supervisor pattern): (owner_id, fencing_token) of a
        # lease held and heartbeated by an external orchestrator. The worker
        # adopts it instead of acquiring: fence-checks instead of heartbeats,
        # and never releases. Pass the lease owner's id as owner_id to
        # execute(); anything else is refused by the fence.
        if adopt_lease is not None:
            if (
                not isinstance(adopt_lease, tuple)
                or len(adopt_lease) != 2
                or not isinstance(adopt_lease[1], int)
                or isinstance(adopt_lease[1], bool)
                or adopt_lease[1] <= 0
            ):
                raise ValueError("adopt_lease must be (owner_id, fencing_token)")
            _require_id(adopt_lease[0], "adopt_lease owner_id")
        self._adopt_lease = adopt_lease
        if crash_hook is not None and not callable(crash_hook):
            raise ValueError("crash_hook must be callable")
        # Test-only fault injection: called with a site name at instrumented
        # points (tool ledger sites and checkpoint sites); may raise
        # SimulatedCrash to model kill -9. Never set in production.
        self._crash_hook = crash_hook
        self._exec_owner: str | None = None
        resolved_ledger_path = (
            Path(ledger_path).absolute()
            if ledger_path is not None
            else store.path.parent / (store.path.name + ".ledger.json")
        )
        self.tool_ledger = ToolEffectLedger(
            store,
            run_id=run.run_id,
            ledger_path=resolved_ledger_path,
            append=self._ledger_append,
            crash_hook=crash_hook,
        )
        # Optional clock (epoch seconds) used to heartbeat the execution
        # lease before each step. Without one, a run that outlasts the TTL
        # loses its lease mid-execution; pass time.time (or a fake in tests)
        # for long-running steps.
        self._clock = clock
        # Optional renewal cadence (seconds) for a background thread that
        # keeps the lease alive *while* a single step action executes. Without
        # it, only the pre-step heartbeat exists and a long action can outlast
        # the TTL mid-execution.
        self._heartbeat_interval = heartbeat_interval_seconds
        self._fence_lock = threading.Lock()
        self._fencing_token: int | None = None
        if self.evidence_sink is not None:
            # Recover any event that reached EventStore before a crash but did
            # not yet reach the evidence ledger. Idempotent source_ids make
            # replay safe after an uncertain evidence commit.
            self._sync_evidence_history(self.store.read_history(self.run.run_id))

    def _sync_evidence_history(self, history) -> None:
        if self.evidence_sink is None:
            return
        if self.evidence_sink.last_sequence > len(history):
            raise ValueError("evidence sink is ahead of the durable event history")
        for event in history[self.evidence_sink.last_sequence :]:
            payload_bytes = self.store.read_blob(event)
            self.evidence_sink.append_event(event, payload_bytes=payload_bytes)

    def _get_token(self) -> int | None:
        with self._fence_lock:
            return self._fencing_token

    def _set_token(self, token: int | None) -> None:
        with self._fence_lock:
            self._fencing_token = token

    def _check_fence(self, owner_id: str) -> None:
        """Raise :class:`FencingError` unless this owner holds the live epoch."""
        token = self._get_token()
        if token is None:
            return
        self.lease.check_token(owner_id, token=token)

    def _is_fenced(self, owner_id: str) -> bool:
        token = self._get_token()
        if token is None:
            return False
        try:
            self.lease.check_token(owner_id, token=token)
        except FencingError:
            return True
        return False

    def _event(
        self,
        *,
        event_id: str,
        sequence: int,
        event_type: str,
        status: str,
        step_id: str,
        idempotency_key: str,
        occurred_at: int,
        payload_digest: str,
        blob_ref: str | None,
    ):
        from durable_contract import EventContract

        return EventContract.from_dict(
            {
                "schema_version": EVENT_SCHEMA_VERSION,
                "event_id": event_id,
                "task_id": self.run.task_id,
                "thread_id": self.run.thread_id,
                "run_id": self.run.run_id,
                "step_id": step_id,
                "sequence": sequence,
                "event_type": event_type,
                "status": status,
                "occurred_at": occurred_at,
                "idempotency_key": idempotency_key,
                "trace_id": self.run.trace_id,
                "payload_digest": payload_digest,
                "blob_ref": blob_ref,
            }
        )

    def _append(
        self,
        *,
        event_type: str,
        status: str,
        step_id: str,
        idempotency_key: str,
        now: int,
        payload: Any,
        owner_id: str | None = None,
    ) -> None:
        token = self._get_token()
        if token is not None:
            # Inside a fencing epoch every append must prove it still holds
            # the current token. A mismatch means the lease was taken over:
            # the write is refused instead of interleaving a dead epoch's
            # events with the new holder's stream.
            if owner_id is None:
                raise ValueError("owner_id is required once a fencing epoch is active")
            self.lease.check_token(owner_id, token=token)
        history = self.store.read_history(self.run.run_id)
        self._sync_evidence_history(history)
        raw_payload = _canonical_json(payload)
        # Claim-check: large payloads never go inline into the JSONL
        # history. They are stored once in the content-addressed blob area
        # and the event carries only the blob_ref (which equals the payload
        # digest — the blob is named by what it contains).
        # Evidence capture needs a durable artifact reference even for small
        # payloads. Without an attached sink, preserve the normal claim-check
        # threshold and storage behavior.
        blob_ref = (
            self.store.blob_store.put(raw_payload)
            if self.evidence_sink is not None or len(raw_payload) >= CLAIM_CHECK_THRESHOLD_BYTES
            else None
        )
        event = self._event(
            event_id=f"event-{len(history) + 1:06d}",
            sequence=len(history) + 1,
            event_type=event_type,
            status=status,
            step_id=step_id,
            idempotency_key=idempotency_key,
            occurred_at=now,
            payload_digest=_digest(payload),
            blob_ref=blob_ref,
        )
        persisted = self.store.append_event(event)
        if self.evidence_sink is not None:
            payload_bytes = self.store.read_blob(persisted)
            self.evidence_sink.append_event(persisted, payload_bytes=payload_bytes)

    def _ledger_append(self, **kwargs: Any) -> None:
        """Append a tool-ledger event inside the active execution's fence."""
        owner_id = self._exec_owner
        if owner_id is None:
            raise ValueError("tool effects require an active execute() call")
        self._append(owner_id=owner_id, **kwargs)

    def _crash(self, site: str) -> None:
        if self._crash_hook is not None:
            self._crash_hook(site)

    def run_tool(
        self,
        *,
        step_id: str,
        tool_call_id: str,
        fn: Callable[[str], Any],
        now: int,
        idempotency_key: str | None = None,
        receiver: Any | None = None,
    ) -> Any:
        """Execute one tool effect with three-state ledger reconcile.

        Intended for use inside step actions: the action calls this per tool
        invocation instead of invoking the tool directly. ``fn`` receives the
        idempotency key for this attempt and must route the raw effect
        through ``receiver.execute(key, ...)`` when a receiver is in play.
        On resume, completed effects replay their cached result without
        re-executing; ambiguous (started, never completed) effects are
        reconciled against ``receiver`` (see :mod:`tool_ledger`). Must be
        called inside :meth:`execute`.
        """
        _require_id(step_id, "step_id")
        return self.tool_ledger.run_tool(
            step_id=step_id,
            tool_call_id=tool_call_id,
            fn=fn,
            now=now,
            idempotency_key=idempotency_key,
            receiver=receiver,
        )

    def prepare(self, *, owner_id: str, now: int) -> dict[str, Any]:
        _require_id(owner_id, "owner_id")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        # A new prepare starts outside any fencing epoch: the lease (and its
        # token) is only established by _ensure_execution_lease below.
        self._set_token(None)
        history = self.store.read_history(self.run.run_id)
        if not history:
            self._append(
                event_type="run.created",
                status="planned",
                step_id="__run__",
                idempotency_key=f"{self.run.run_id}-created",
                now=now,
                payload=self.run.to_dict(),
            )
        return self.store.derive_state(self.run.run_id)

    def _ensure_execution_lease(self, owner_id: str, *, now: int) -> int:
        # An expired lease is acquirable (crash recovery): LeaseManager.acquire
        # already encodes that rule, so fall through to it when the existing
        # lease is not valid for this owner. An active foreign lease is still
        # refused by acquire, and a corrupt lease file still fails closed.
        # Returns the fencing token of the epoch this holder now owns.
        if self._adopt_lease is not None:
            # Supervisor pattern: the lease is held and heartbeated by an
            # external orchestrator. Adopt it — assert it is valid for the
            # adopted owner and that the epoch token matches. No takeover,
            # no run.fenced marker, no new epoch.
            adopted_owner, adopted_token = self._adopt_lease
            if owner_id != adopted_owner:
                raise FencingError(
                    "adopted lease requires the lease owner's id"
                )
            current = self.lease.assert_valid(adopted_owner, now=now)
            if current["fencing_token"] != adopted_token:
                raise FencingError(
                    "adopted fencing token mismatch: the lease moved on"
                )
            self._set_token(adopted_token)
            return adopted_token
        prior: dict[str, Any] | None = None
        if self.lease.path.exists():
            try:
                current = self.lease.assert_valid(owner_id, now=now)
                token = current["fencing_token"]
                self._set_token(token)
                return token
            except ValueError:
                pass
            try:
                prior = self.lease._read()
            except ValueError:
                prior = None
        lease = self.lease.acquire(
            owner_id, now=now, ttl_seconds=self.lease_ttl_seconds
        )
        token = lease["fencing_token"]
        self._set_token(token)
        if prior is not None:
            # Takeover of a previous epoch: record it as a state-neutral
            # run.fenced marker. It is written by the new legitimate holder
            # (whose token is already active, so the fenced _append gate
            # passes), so a stale holder never has to write after being
            # fenced. The marker carries no state transition — it must not
            # perturb the new epoch's derived run status.
            self._append(
                event_type="run.fenced",
                status="running",
                step_id="__run__",
                idempotency_key=(
                    f"{self.run.run_id}-fenced-{prior['owner_id']}-{prior['fencing_token']}"
                ),
                now=now,
                payload={
                    "fenced_owner_id": prior["owner_id"],
                    "fenced_token": prior["fencing_token"],
                    "owner_id": owner_id,
                    "fencing_token": token,
                },
                owner_id=owner_id,
            )
        return token

    def _release_quietly(self, owner_id: str) -> None:
        """Release the execution lease without masking the run outcome.

        If the lease expired mid-run and was taken over, it is no longer
        ours: raising here would destroy the result the run just produced.
        With an adopted lease the supervisor owns the lifecycle, so the
        worker never releases.
        """
        if self._adopt_lease is not None:
            return
        try:
            self.lease.release(owner_id)
        except ValueError:
            pass

    def _heartbeat(self, owner_id: str) -> None:
        """Refresh the execution lease before a step action, if clocked.

        A lost lease aborts the run instead of executing steps unowned:
        heartbeat raises (via assert_valid, or FencingError on a token
        mismatch when the lease was taken over), and the outer handler
        records the failure honestly.

        With an adopted lease the supervisor heartbeats; the worker only
        fence-checks (verify the epoch is still ours, never extend it).
        """
        if self._adopt_lease is not None:
            self._check_fence(owner_id)
            return
        if self._clock is None:
            return
        now = self._clock()
        if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
            raise ValueError("clock must return a positive integer")
        token = self._get_token()
        if token is None:
            raise ValueError("cannot heartbeat without a fencing epoch")
        self.lease.heartbeat(
            owner_id, token=token, now=now, ttl_seconds=self.lease_ttl_seconds
        )

    def _run_action_with_heartbeat(
        self, owner_id: str, action: Callable[[], dict[str, Any]]
    ) -> dict[str, Any]:
        """Run one step action, renewing the lease from a daemon thread.

        Without this, a single action longer than the TTL lets the lease lapse
        mid-execution. With ``heartbeat_interval_seconds`` set, a daemon
        thread renews the lease on that cadence while the action runs. If the
        lease is lost mid-action (taken over), the action is not killed — it
        cannot be — but its result is never written: :class:`FencingError` is
        raised after the action returns instead of appending a stale
        ``step.finished``.
        """
        if self._heartbeat_interval is None:
            return action()
        if self._clock is None:  # guarded by __init__; fail closed anyway
            raise ValueError("heartbeat_interval_seconds requires a clock")
        stop = threading.Event()
        failures: list[BaseException] = []

        def _renew_loop() -> None:
            while not stop.wait(self._heartbeat_interval):
                try:
                    now = self._clock()
                    if not isinstance(now, int) or isinstance(now, bool) or now <= 0:
                        raise ValueError("clock must return a positive integer")
                    token = self._get_token()
                    if token is None:
                        raise ValueError("fencing epoch ended during step action")
                    renewed = self.lease.renew(
                        owner_id,
                        token=token,
                        now=now,
                        ttl_seconds=self.lease_ttl_seconds,
                    )
                    self._set_token(renewed["fencing_token"])
                except BaseException as error:  # recorded, then surfaced below
                    failures.append(error)
                    return

        thread = threading.Thread(
            target=_renew_loop, daemon=True, name="northstar-lease-heartbeat"
        )
        thread.start()
        try:
            result = action()
        except BaseException:
            stop.set()
            thread.join(timeout=self._heartbeat_interval + 5)
            raise
        stop.set()
        thread.join(timeout=self._heartbeat_interval + 5)
        if failures:
            raise FencingError(
                f"execution lease lost during step action: {failures[0]}"
            ) from failures[0]
        return result

    def _append_run_started(self, *, now: int, owner_id: str) -> None:
        state = self.store.derive_state(self.run.run_id)
        if state["status"] == "planned":
            self._append(
                event_type="run.started",
                status="running",
                step_id="__run__",
                idempotency_key=f"{self.run.run_id}-started",
                now=now,
                payload={"status": "running"},
                owner_id=owner_id,
            )
        elif state["status"] == "waiting":
            self._append(
                event_type="run.started",
                status="running",
                step_id="__run__",
                idempotency_key=f"{self.run.run_id}-resumed-{state['sequence'] + 1}",
                now=now,
                payload={"status": "running"},
                owner_id=owner_id,
            )

    def _write_checkpoint(self, *, owner_id: str) -> None:
        """Persist a checkpoint, with crash-injection sites around it."""
        self._crash("before-checkpoint")
        self.store.create_checkpoint(self.run.run_id)
        self._crash("after-checkpoint")

    def cancel(self, *, owner_id: str, now: int) -> dict[str, Any]:
        state = self.prepare(owner_id=owner_id, now=now)
        if state["status"] in {"finished", "failed", "cancelled"}:
            return state
        self._append(
            event_type="run.cancelled",
            status="cancelled",
            step_id="__run__",
            idempotency_key=f"{self.run.run_id}-cancelled-{state['sequence'] + 1}",
            now=now,
            payload={"status": "cancelled"},
        )
        return self.store.derive_state(self.run.run_id)

    def execute(
        self,
        plans: list[StepPlan],
        *,
        owner_id: str,
        now: int,
        finalize: bool = True,
    ) -> dict[str, Any]:
        if not isinstance(plans, list):
            raise ValueError("plans must be a list")
        if len({plan.step_id for plan in plans}) != len(plans):
            raise ValueError("step plans must have unique step IDs")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        if now >= self.run.deadline_at:
            raise ValueError("run deadline has expired")
        state = self.prepare(owner_id=owner_id, now=now)
        if state["status"] == "cancelled":
            return state
        if state["status"] == "finished":
            return state
        if state["status"] == "failed":
            raise ValueError("run has already failed")

        self._ensure_execution_lease(owner_id, now=now)
        # Tool effects run inside this execution: bind the ledger's appends
        # to the fencing epoch's owner for the duration of execute().
        self._exec_owner = owner_id
        try:
            self._append_run_started(now=now, owner_id=owner_id)
            for plan in plans:
                self._heartbeat(owner_id)
                state = self.store.derive_state(self.run.run_id)
                step_state = state["steps"].get(plan.step_id)
                if step_state is not None and step_state["status"] == "finished":
                    continue
                if step_state is None:
                    self._append(
                        event_type="step.planned",
                        status="planned",
                        step_id=plan.step_id,
                        idempotency_key=f"{self.run.run_id}-{plan.step_id}-planned",
                        now=now,
                        payload={
                            "input_digest": plan.input_digest,
                            "scope_snapshot": list(plan.scope_snapshot),
                            "expected_postconditions": list(plan.expected_postconditions),
                        },
                        owner_id=owner_id,
                    )
                    step_state = {"status": "planned"}
                if step_state["status"] == "failed":
                    raise ValueError(f"step {plan.step_id} has already failed")
                if step_state["status"] == "planned":
                    self._append(
                        event_type="step.started",
                        status="running",
                        step_id=plan.step_id,
                        idempotency_key=f"{self.run.run_id}-{plan.step_id}-started",
                        now=now,
                        payload={"input_digest": plan.input_digest},
                        owner_id=owner_id,
                    )
                action_key = f"{self.run.run_id}:{plan.step_id}:attempt-1"
                try:
                    output = self._run_action_with_heartbeat(
                        owner_id, lambda: plan.action(action_key)
                    )
                    if not isinstance(output, dict):
                        raise ValueError("step action must return an object")
                except KeyboardInterrupt:
                    raise
                except BaseException:
                    raise
                # Prove the fencing epoch is still ours before the action's
                # result lands: a holder whose lease was taken over mid-action
                # must not append step.finished into the new holder's stream.
                self._check_fence(owner_id)
                self._append(
                    event_type="step.finished",
                    status="finished",
                    step_id=plan.step_id,
                    idempotency_key=f"{self.run.run_id}-{plan.step_id}-finished",
                    now=now,
                    payload={"output_digest": _digest(output)},
                    owner_id=owner_id,
                )
                self._append(
                    event_type="checkpoint.created",
                    status="running",
                    step_id="__run__",
                    idempotency_key=f"{self.run.run_id}-checkpoint-{plan.step_id}",
                    now=now,
                    payload=self.store.derive_state(self.run.run_id),
                    owner_id=owner_id,
                )
                self._write_checkpoint(owner_id=owner_id)

            state = self.store.derive_state(self.run.run_id)
            if finalize and state["status"] == "running":
                self._append(
                    event_type="run.finished",
                    status="finished",
                    step_id="__run__",
                    idempotency_key=f"{self.run.run_id}-finished",
                    now=now,
                    payload={"status": "finished"},
                    owner_id=owner_id,
                )
                self._write_checkpoint(owner_id=owner_id)
            return self.store.derive_state(self.run.run_id)
        except KeyboardInterrupt:
            raise
        except Exception as error:
            if isinstance(error, FencingError) or self._is_fenced(owner_id):
                # The epoch was fenced: writing step.failed/run.failed now
                # would interleave a dead epoch's markers with the new
                # holder's event stream, which is exactly what fencing
                # forbids. Stop writing and surface the fence loudly.
                raise
            state = self.store.derive_state(self.run.run_id)
            active_step = next(
                (
                    step_id
                    for step_id, details in state["steps"].items()
                    if details["status"] == "running"
                ),
                None,
            )
            if active_step is not None:
                self._append(
                    event_type="step.failed",
                    status="failed",
                    step_id=active_step,
                    idempotency_key=f"{self.run.run_id}-{active_step}-failed",
                    now=now,
                    payload={"error_class": error.__class__.__name__},
                    owner_id=owner_id,
                )
            if self.store.derive_state(self.run.run_id)["status"] == "running":
                self._append(
                    event_type="run.failed",
                    status="failed",
                    step_id="__run__",
                    idempotency_key=f"{self.run.run_id}-failed",
                    now=now,
                    payload={"error_class": error.__class__.__name__},
                    owner_id=owner_id,
                )
            return self.store.derive_state(self.run.run_id)
        finally:
            self._exec_owner = None
            self._release_quietly(owner_id)
