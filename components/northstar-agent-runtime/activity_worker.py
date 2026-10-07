"""Activity worker: Temporal-activities-shaped execution bookkeeping.

Research motivation: in Temporal a *workflow* orchestrates durable
execution while an *activity worker* does the actual side-effecting
work -- calling an API, writing to a database, running a model. The
worker polls a task queue, starts one activity execution per task
token, and keeps the lease alive with periodic *heartbeats* that carry
progress details. If the worker crashes without a heartbeat the
activity times out and is retried; when the work finishes the worker
completes the execution with a result payload, or fails it with a
typed error that the retry policy may re-drive. The Temporal server
books all of this: who started what, which heartbeats arrived, and the
declared outcome.

This module books that lifecycle deterministically on a single host.
It executes no activity code, polls no queue, and sends no heartbeat
over a wire: it is the *ledger* -- declared activity types, started
executions, host-reported heartbeats, declared completions, failures
and cancellations.

Public API:

- ``ActivityWorker(worker_id, task_queue)`` -- mutable, RLock-guarded
  ledger.
  - ``register_activity(activity_type, seq)`` -> frozen
    ``ActivityTypeRecord``: registers one activity type by name.
  - ``execute(task_token, activity_type, seq, payload_digest="")`` ->
    frozen ``ExecutionRecord``: starts one execution of a registered
    type (status ``running``).
  - ``heartbeat(task_token, seq, progress_digest="")`` -> frozen
    ``HeartbeatRecord``: books one heartbeat on a running execution;
    ``heartbeat_seq`` counts per execution from 1.
  - ``complete(task_token, seq, result_digest="")`` -> frozen
    ``CompletionRecord``: terminal -- declares the execution
    ``completed`` with a result pinned by ``sha256:`` digest.
  - ``fail(task_token, seq, error_type)`` -> frozen ``FailureRecord``:
    terminal -- declares the execution ``failed``; ``error_type`` is a
    pinned vocabulary (``application``/``timeout``/``cancelled``/
    ``terminated``/``retryable``).
  - ``cancel(task_token, seq, reason="")`` -> frozen
    ``CancellationRecord``: terminal -- declares the execution
    ``cancelled`` before it completed or failed.
  - ``execution(task_token)`` / ``executions()`` / ``heartbeats()`` /
    ``stats()`` / ``audit_log()`` -- pure read views; consume no seq.
- ``activity_worker_audit_event(kind, seq, **detail)`` --
  ``audit.ndjson/1`` records: ``"activity-worker.registered"``,
  ``"activity-worker.started"``, ``"activity-worker.heartbeated"``,
  ``"activity-worker.completed"``, ``"activity-worker.failed"``,
  ``"activity-worker.cancelled"``, ``"activity-worker.rejected"``.

Payload, result and progress bytes never enter a record: they travel
as ``sha256:`` digest pins only, and raw keys (``payload``,
``result``, ``progress``, ``bytes``) are banned from the audit
boundary.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq and book an
``"activity-worker.rejected"`` row; malformed seqs raise bare and
consume nothing), RLock-guarded, fail-closed taxonomy, stdlib-only
(``canonical_json`` sibling helper behind the standard try/except
fallback).

Honest scope:

- This module books *declared* executions and host-reported heartbeats;
  it observes no task queue, runs no activity function, and cannot
  prove a booked ``completed`` was actually produced by real work.
- A ``HeartbeatRecord`` proves a ``heartbeat()`` call happened in this
  ledger; liveness across a network crash is the host's problem.
- Failure ``error_type`` is a host declaration, not a diagnosis.

Version pin: ``activity-worker.v1`` / schema pin
``northstar.activity-worker.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
ACTIVITY_WORKER_VERSION = "activity-worker.v1"

#: Schema pin carried by records and audit events.
ACTIVITY_WORKER_SCHEMA = "northstar.activity-worker.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_REGISTERED = "activity-worker.registered"
KIND_STARTED = "activity-worker.started"
KIND_HEARTBEATED = "activity-worker.heartbeated"
KIND_COMPLETED = "activity-worker.completed"
KIND_FAILED = "activity-worker.failed"
KIND_CANCELLED = "activity-worker.cancelled"
KIND_REJECTED = "activity-worker.rejected"

_LEDGER_KINDS = frozenset(
    {
        KIND_REGISTERED,
        KIND_STARTED,
        KIND_HEARTBEATED,
        KIND_COMPLETED,
        KIND_FAILED,
        KIND_CANCELLED,
        KIND_REJECTED,
    }
)

#: Detail keys that must never cross the audit boundary (raw bytes pins
#: only; the bytes themselves stay host-side).
_BANNED_DETAIL_KEYS = frozenset(
    {
        "payload",
        "payload_bytes",
        "result",
        "result_bytes",
        "progress",
        "progress_bytes",
        "message",
        "bytes",
        "value",
        "data",
    }
)

#: Digest pins are always ``sha256:`` + 64 lowercase hex characters.
_HEX64 = set("0123456789abcdef")

#: Pinned failure-type vocabulary (Temporal-shaped failure categories).
ERROR_TYPES = frozenset(
    {"application", "timeout", "cancelled", "terminated", "retryable"}
)

#: Execution statuses this ledger recognizes.
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
_STATUSES = frozenset(
    {STATUS_RUNNING, STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED}
)


# --- error taxonomy --------------------------------------------------------


class ActivityWorkerError(Exception):
    """Base class for every fail-closed refusal in this module."""


class BadWorkerError(ActivityWorkerError):
    """Worker id / task queue shape is malformed."""


class BadActivityTypeError(ActivityWorkerError):
    """Activity type name is malformed."""


class DuplicateActivityError(ActivityWorkerError):
    """Activity type is already registered."""


class UnknownActivityError(ActivityWorkerError):
    """No such registered activity type."""


class BadTaskError(ActivityWorkerError):
    """Task token shape is malformed."""


class DuplicateTaskError(ActivityWorkerError):
    """Task token is already booked (ids are never recycled)."""


class UnknownTaskError(ActivityWorkerError):
    """No such booked execution."""


class TaskStateError(ActivityWorkerError):
    """The operation is invalid in the execution's current state."""


class BadDigestError(ActivityWorkerError):
    """A digest pin is not ``sha256:`` + 64 lowercase hex."""


class BadErrorTypeError(ActivityWorkerError):
    """Failure ``error_type`` is outside the pinned vocabulary."""


class SeqOrderError(ActivityWorkerError):
    """Caller seq did not strictly increase."""


# --- input validation ------------------------------------------------------


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"{name} must be an int seq, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"{name} must be non-negative, got {seq}")
    return seq


def _check_text(value: Any, name: str, max_len: int = 256) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadWorkerError(f"{name} must be a string, got {type(value).__name__}")
    value = value.strip()
    if not value:
        raise BadWorkerError(f"{name} must be non-empty")
    if len(value) > max_len:
        raise BadWorkerError(f"{name} exceeds {max_len} chars")
    return value


def _check_activity_type(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadActivityTypeError(
            f"activity_type must be a string, got {type(value).__name__}"
        )
    value = value.strip()
    if not value:
        raise BadActivityTypeError("activity_type must be non-empty")
    if len(value) > 256:
        raise BadActivityTypeError("activity_type exceeds 256 chars")
    return value


def _check_task_token(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadTaskError(
            f"task_token must be a string, got {type(value).__name__}"
        )
    value = value.strip()
    if not value:
        raise BadTaskError("task_token must be non-empty")
    if len(value) > 256:
        raise BadTaskError("task_token exceeds 256 chars")
    return value


def _check_digest(value: Any, name: str) -> str:
    """Validate a ``sha256:<64hex>`` pin; empty string means 'absent'."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{name} must be a string, got {type(value).__name__}")
    if value == "":
        return ""
    if len(value) != 7 + 64 or not value.startswith("sha256:"):
        raise BadDigestError(f"{name} must look like 'sha256:' + 64 hex chars")
    if any(c not in _HEX64 for c in value[7:]):
        raise BadDigestError(f"{name} must be lowercase hex")
    return value


def _check_error_type(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadErrorTypeError(
            f"error_type must be a string, got {type(value).__name__}"
        )
    if value not in ERROR_TYPES:
        raise BadErrorTypeError(
            f"error_type must be one of {sorted(ERROR_TYPES)}, got {value!r}"
        )
    return value


def _pin_bytes(data: bytes) -> str:
    """Convenience digest pin (host-side only; pins enter records)."""
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        dumped = _cj.jcs_dumps(obj)  # type: ignore[attr-defined]
        return dumped.encode("utf-8") if isinstance(dumped, str) else dumped
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_of(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()


# --- audit builder -----------------------------------------------------------


def activity_worker_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the activity ledger."""
    if kind not in _LEDGER_KINDS:
        raise ActivityWorkerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    banned = _BANNED_DETAIL_KEYS.intersection(detail)
    if banned:
        raise ActivityWorkerError(
            f"detail carries banned keys: {sorted(banned)}"
        )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "activity-worker",
        "module_version": ACTIVITY_WORKER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# --- frozen records ----------------------------------------------------------


@dataclass(frozen=True)
class ActivityTypeRecord:
    """One registered activity type."""

    worker_id: str
    activity_type: str
    seq: int
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "worker_id": self.worker_id,
                    "activity_type": self.activity_type,
                }
            ),
        )

    def verify(self) -> bool:
        """Recompute the pin; True when untampered."""
        return self.digest == _digest_of(
            {"worker_id": self.worker_id, "activity_type": self.activity_type}
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "activity_type": self.activity_type,
            "seq": self.seq,
            "digest": self.digest,
            "schema": ACTIVITY_WORKER_SCHEMA,
        }


@dataclass(frozen=True)
class ExecutionRecord:
    """One started activity execution (status ``running``)."""

    worker_id: str
    task_token: str
    activity_type: str
    seq: int
    payload_digest: str = ""
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "worker_id": self.worker_id,
                    "task_token": self.task_token,
                    "activity_type": self.activity_type,
                    "payload_digest": self.payload_digest,
                }
            ),
        )

    def verify(self) -> bool:
        return self.digest == _digest_of(
            {
                "worker_id": self.worker_id,
                "task_token": self.task_token,
                "activity_type": self.activity_type,
                "payload_digest": self.payload_digest,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "task_token": self.task_token,
            "activity_type": self.activity_type,
            "seq": self.seq,
            "payload_digest": self.payload_digest,
            "digest": self.digest,
            "schema": ACTIVITY_WORKER_SCHEMA,
        }


@dataclass(frozen=True)
class HeartbeatRecord:
    """One heartbeat booked on a running execution."""

    task_token: str
    heartbeat_seq: int
    seq: int
    progress_digest: str = ""
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "task_token": self.task_token,
                    "heartbeat_seq": self.heartbeat_seq,
                    "progress_digest": self.progress_digest,
                }
            ),
        )

    def verify(self) -> bool:
        return self.digest == _digest_of(
            {
                "task_token": self.task_token,
                "heartbeat_seq": self.heartbeat_seq,
                "progress_digest": self.progress_digest,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "task_token": self.task_token,
            "heartbeat_seq": self.heartbeat_seq,
            "seq": self.seq,
            "progress_digest": self.progress_digest,
            "digest": self.digest,
            "schema": ACTIVITY_WORKER_SCHEMA,
        }


@dataclass(frozen=True)
class CompletionRecord:
    """Terminal declaration: the execution completed with a result."""

    task_token: str
    seq: int
    result_digest: str = ""
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "task_token": self.task_token,
                    "result_digest": self.result_digest,
                }
            ),
        )

    def verify(self) -> bool:
        return self.digest == _digest_of(
            {
                "task_token": self.task_token,
                "result_digest": self.result_digest,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "task_token": self.task_token,
            "seq": self.seq,
            "result_digest": self.result_digest,
            "digest": self.digest,
            "schema": ACTIVITY_WORKER_SCHEMA,
        }


@dataclass(frozen=True)
class FailureRecord:
    """Terminal declaration: the execution failed with a typed error."""

    task_token: str
    error_type: str
    seq: int
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "task_token": self.task_token,
                    "error_type": self.error_type,
                }
            ),
        )

    def verify(self) -> bool:
        return self.digest == _digest_of(
            {
                "task_token": self.task_token,
                "error_type": self.error_type,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "task_token": self.task_token,
            "error_type": self.error_type,
            "seq": self.seq,
            "digest": self.digest,
            "schema": ACTIVITY_WORKER_SCHEMA,
        }


@dataclass(frozen=True)
class CancellationRecord:
    """Terminal declaration: the execution was cancelled by the host."""

    task_token: str
    seq: int
    reason: str = ""
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "task_token": self.task_token,
                    "reason": self.reason,
                }
            ),
        )

    def verify(self) -> bool:
        return self.digest == _digest_of(
            {
                "task_token": self.task_token,
                "reason": self.reason,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "task_token": self.task_token,
            "seq": self.seq,
            "reason": self.reason,
            "digest": self.digest,
            "schema": ACTIVITY_WORKER_SCHEMA,
        }


# --- the ledger ----------------------------------------------------------------


class ActivityWorker:
    """Deterministic bookkeeping for one worker's activity executions.

    Distinct from any real Temporal worker: this ledger only *books* --
    which activity types were registered (``register_activity``), which
    executions were started (``execute``), the host-reported heartbeats
    (``heartbeat``), and the declared terminal outcomes (``complete`` /
    ``fail`` / ``cancel``). All mutations take a caller-supplied
    strictly increasing ``seq``; failed mutations consume their seq and
    book an ``"activity-worker.rejected"`` audit row (batch discipline).
    Terminal outcomes are final: later mutations on that task token
    raise :class:`TaskStateError`. Views consume no seq and write no
    audit rows.
    """

    def __init__(self, worker_id: str, task_queue: str):
        self._worker_id = _check_text(worker_id, "worker_id")
        self._task_queue = _check_text(task_queue, "task_queue")
        self._lock = threading.RLock()
        self._last_seq = -1
        self._types: Dict[str, ActivityTypeRecord] = {}
        self._executions: Dict[str, ExecutionRecord] = {}
        self._status: Dict[str, str] = {}
        self._heartbeats: Dict[str, list] = {}
        self._terminals: Dict[str, Mapping[str, Any]] = {}
        self._audit: list = []

    # -- seq discipline ------------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)  # malformed seq raises, consumes nothing
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must strictly increase (last={self._last_seq}, got={seq})"
                )
            self._last_seq = seq
        return seq

    def _fail(self, seq: int, exc: ActivityWorkerError, **detail: Any) -> "None":
        """Book a rejection audit row, then raise the given error."""
        with self._lock:
            self._audit.append(
                activity_worker_audit_event(
                    KIND_REJECTED, seq, reason=str(exc), **detail
                )
            )
        raise exc

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        with self._lock:
            self._audit.append(
                activity_worker_audit_event(kind, seq, **detail)
            )

    # -- mutations ------------------------------------------------------------

    def register_activity(
        self, activity_type: str, seq: int
    ) -> ActivityTypeRecord:
        """Register one activity type on this worker."""
        seq = self._claim(seq)
        activity_type = _check_activity_type(activity_type)
        with self._lock:
            if activity_type in self._types:
                self._fail(
                    seq,
                    DuplicateActivityError(
                        f"activity type already registered: {activity_type!r}"
                    ),
                    activity_type=activity_type,
                )
            record = ActivityTypeRecord(
                worker_id=self._worker_id,
                activity_type=activity_type,
                seq=seq,
            )
            self._types[activity_type] = record
        self._emit(
            KIND_REGISTERED,
            seq,
            worker_id=self._worker_id,
            activity_type=activity_type,
        )
        return record

    def execute(
        self,
        task_token: str,
        activity_type: str,
        seq: int,
        payload_digest: str = "",
    ) -> ExecutionRecord:
        """Start one execution of a registered activity type."""
        seq = self._claim(seq)
        task_token = _check_task_token(task_token)
        activity_type = _check_activity_type(activity_type)
        payload_digest = _check_digest(payload_digest, "payload_digest")
        with self._lock:
            if task_token in self._executions:
                self._fail(
                    seq,
                    DuplicateTaskError(
                        f"task token already booked: {task_token!r}"
                    ),
                    task_token=task_token,
                )
            if activity_type not in self._types:
                self._fail(
                    seq,
                    UnknownActivityError(
                        f"no such activity type: {activity_type!r}"
                    ),
                    activity_type=activity_type,
                )
            record = ExecutionRecord(
                worker_id=self._worker_id,
                task_token=task_token,
                activity_type=activity_type,
                seq=seq,
                payload_digest=payload_digest,
            )
            self._executions[task_token] = record
            self._status[task_token] = STATUS_RUNNING
            self._heartbeats[task_token] = []
        self._emit(
            KIND_STARTED,
            seq,
            worker_id=self._worker_id,
            task_token=task_token,
            activity_type=activity_type,
        )
        return record

    def heartbeat(
        self,
        task_token: str,
        seq: int,
        progress_digest: str = "",
    ) -> HeartbeatRecord:
        """Book one heartbeat on a running execution."""
        seq = self._claim(seq)
        task_token = _check_task_token(task_token)
        progress_digest = _check_digest(progress_digest, "progress_digest")
        with self._lock:
            execution = self._executions.get(task_token)
            if execution is None:
                self._fail(
                    seq,
                    UnknownTaskError(f"no such task: {task_token!r}"),
                    task_token=task_token,
                )
            if self._status.get(task_token) != STATUS_RUNNING:
                self._fail(
                    seq,
                    TaskStateError(
                        f"task {task_token!r} is "
                        f"{self._status.get(task_token)!r}, not running"
                    ),
                    task_token=task_token,
                )
            beats = self._heartbeats[task_token]
            record = HeartbeatRecord(
                task_token=task_token,
                heartbeat_seq=len(beats) + 1,
                seq=seq,
                progress_digest=progress_digest,
            )
            beats.append(record)
        self._emit(
            KIND_HEARTBEATED,
            seq,
            task_token=task_token,
            heartbeat_seq=record.heartbeat_seq,
        )
        return record

    def complete(
        self,
        task_token: str,
        seq: int,
        result_digest: str = "",
    ) -> CompletionRecord:
        """Declare an execution completed; terminal."""
        seq = self._claim(seq)
        task_token = _check_task_token(task_token)
        result_digest = _check_digest(result_digest, "result_digest")
        with self._lock:
            execution = self._executions.get(task_token)
            if execution is None:
                self._fail(
                    seq,
                    UnknownTaskError(f"no such task: {task_token!r}"),
                    task_token=task_token,
                )
            if self._status.get(task_token) != STATUS_RUNNING:
                self._fail(
                    seq,
                    TaskStateError(
                        f"task {task_token!r} is already "
                        f"{self._status.get(task_token)!r}"
                    ),
                    task_token=task_token,
                )
            record = CompletionRecord(
                task_token=task_token, seq=seq, result_digest=result_digest
            )
            self._status[task_token] = STATUS_COMPLETED
            self._terminals[task_token] = record
        self._emit(KIND_COMPLETED, seq, task_token=task_token)
        return record

    def fail(
        self, task_token: str, seq: int, error_type: str
    ) -> FailureRecord:
        """Declare an execution failed; terminal."""
        seq = self._claim(seq)
        task_token = _check_task_token(task_token)
        error_type = _check_error_type(error_type)
        with self._lock:
            execution = self._executions.get(task_token)
            if execution is None:
                self._fail(
                    seq,
                    UnknownTaskError(f"no such task: {task_token!r}"),
                    task_token=task_token,
                )
            if self._status.get(task_token) != STATUS_RUNNING:
                self._fail(
                    seq,
                    TaskStateError(
                        f"task {task_token!r} is already "
                        f"{self._status.get(task_token)!r}"
                    ),
                    task_token=task_token,
                )
            record = FailureRecord(
                task_token=task_token, error_type=error_type, seq=seq
            )
            self._status[task_token] = STATUS_FAILED
            self._terminals[task_token] = record
        self._emit(
            KIND_FAILED, seq, task_token=task_token, error_type=error_type
        )
        return record

    def cancel(
        self, task_token: str, seq: int, reason: str = ""
    ) -> CancellationRecord:
        """Declare an execution cancelled; terminal."""
        seq = self._claim(seq)
        task_token = _check_task_token(task_token)
        reason = _check_text(reason, "reason", max_len=1024) if reason else ""
        with self._lock:
            execution = self._executions.get(task_token)
            if execution is None:
                self._fail(
                    seq,
                    UnknownTaskError(f"no such task: {task_token!r}"),
                    task_token=task_token,
                )
            if self._status.get(task_token) != STATUS_RUNNING:
                self._fail(
                    seq,
                    TaskStateError(
                        f"task {task_token!r} is already "
                        f"{self._status.get(task_token)!r}"
                    ),
                    task_token=task_token,
                )
            record = CancellationRecord(
                task_token=task_token, seq=seq, reason=reason
            )
            self._status[task_token] = STATUS_CANCELLED
            self._terminals[task_token] = record
        self._emit(KIND_CANCELLED, seq, task_token=task_token)
        return record

    # -- views ----------------------------------------------------------------

    @property
    def worker_id(self) -> str:
        return self._worker_id

    @property
    def task_queue(self) -> str:
        return self._task_queue

    def activity_type(self, activity_type: str) -> ActivityTypeRecord:
        """Pure read view of one registered activity type."""
        activity_type = _check_activity_type(activity_type)
        with self._lock:
            try:
                return self._types[activity_type]
            except KeyError:
                raise UnknownActivityError(
                    f"no such activity type: {activity_type!r}"
                ) from None

    def activity_types(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._types))

    def execution(self, task_token: str) -> ExecutionRecord:
        """Pure read view of one booked execution."""
        task_token = _check_task_token(task_token)
        with self._lock:
            try:
                return self._executions[task_token]
            except KeyError:
                raise UnknownTaskError(
                    f"no such task: {task_token!r}"
                ) from None

    def executions(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._executions))

    def status(self, task_token: str) -> str:
        """Pure read view of one execution's current status."""
        task_token = _check_task_token(task_token)
        with self._lock:
            try:
                return self._status[task_token]
            except KeyError:
                raise UnknownTaskError(
                    f"no such task: {task_token!r}"
                ) from None

    def heartbeats(self, task_token: str) -> Tuple[HeartbeatRecord, ...]:
        """Pure read view of one execution's heartbeats."""
        task_token = _check_task_token(task_token)
        with self._lock:
            if task_token not in self._executions:
                raise UnknownTaskError(
                    f"no such task: {task_token!r}"
                )
            return tuple(self._heartbeats[task_token])

    def terminal(self, task_token: str) -> Optional[Mapping[str, Any]]:
        """Pure read view of a task's terminal record (None if running)."""
        task_token = _check_task_token(task_token)
        with self._lock:
            if task_token not in self._executions:
                raise UnknownTaskError(
                    f"no such task: {task_token!r}"
                )
            return self._terminals.get(task_token)

    def stats(self, seq: int) -> Mapping[str, Any]:
        """Pure read view of ledger counters (validates seq, consumes none)."""
        _check_seq(seq)
        with self._lock:
            counts: Dict[str, int] = {s: 0 for s in sorted(_STATUSES)}
            for status in self._status.values():
                counts[status] += 1
            total_beats = sum(len(beats) for beats in self._heartbeats.values())
            return {
                "schema": ACTIVITY_WORKER_SCHEMA,
                "worker_id": self._worker_id,
                "activity_types": len(self._types),
                "executions": len(self._executions),
                "status_counts": counts,
                "heartbeats": total_beats,
                "seq": seq,
            }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


# --- self check ----------------------------------------------------------------


def main() -> None:
    worker = ActivityWorker("worker-1", "default")
    worker.register_activity("send-email", 1)
    worker.execute("tok-1", "send-email", 2)
    worker.heartbeat("tok-1", 3)
    worker.heartbeat("tok-1", 4)
    worker.complete("tok-1", 5)
    assert worker.status("tok-1") == STATUS_COMPLETED
    assert len(worker.heartbeats("tok-1")) == 2
    stats = worker.stats(6)
    assert stats["status_counts"]["completed"] == 1
    print(
        "activity-worker OK: register, execute, heartbeat, complete, stats"
    )


if __name__ == "__main__":
    main()
