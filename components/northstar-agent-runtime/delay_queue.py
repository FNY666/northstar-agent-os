"""Delay queue: delayed-task delivery bookkeeping.

Research motivation: in Amazon SQS (DelaySeconds), RabbitMQ (delayed
message plugin), Kafka (delayed delivery) and Celery (ETA/countdown), a
delay queue parks a message until its delivery time arrives: the broker
books the intent, and the message becomes visible only when due. This
module books that intent deterministically: schedule with a logical
delay, poll for due tasks, cancel before delivery. It executes no work,
fires no timers, and delivers no message -- the host owns the clock,
the timers, and the actual delivery.

Public API:

- ``DelayQueue()`` -- mutable, RLock-guarded ledger.
  - ``schedule(task_id, payload_digest, delay_seqs, seq)`` -> frozen
    ``ScheduleRecord``: books a delayed task with
    ``ready_at = seq + delay_seqs`` (logical seqs, never wall-clock).
  - ``poll(seq)`` -> frozen ``PollReport``: pure read view of the task
    ids that are due (``ready_at <= seq``); sorted, as data.
  - ``cancel(task_id, seq, reason="")`` -> frozen ``CancelRecord``:
    terminally removes a scheduled task; the id is retired and may
    never be re-scheduled.
  - ``task(task_id)`` / ``pending()`` / ``due_ids(seq)`` / ``stats()`` /
    ``audit_log()`` -- pure read views; consume no seq.
- ``delay_queue_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"delay-queue.scheduled"``,
  ``"delay-queue.cancelled"``, ``"delay-queue.rejected"``.

Payloads are pinned by ``sha256:`` digest only -- raw bytes never enter
a record or cross the audit boundary. Time is caller-supplied logical
seqs; the module cannot prove a task was actually delivered late.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* delays, due tasks and cancellations; it
  observes no clock, fires no timer, and cannot prove a polled task was
  actually delivered by the host.
- A ``PollReport`` is a decision, not a delivery: the message moves
  only if the host acts on it.
- Delay is expressed in logical seqs; mapping logical seqs to
  wall-clock time is the host's policy, not this ledger's.

Version pin: ``delay-queue.v1`` / schema pin
``northstar.delay-queue.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
DELAY_QUEUE_VERSION = "delay-queue.v1"

#: Schema pin carried by records and audit events.
DELAY_QUEUE_SCHEMA = "northstar.delay-queue.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_SCHEDULED = "delay-queue.scheduled"
KIND_CANCELLED = "delay-queue.cancelled"
KIND_REJECTED = "delay-queue.rejected"
_KINDS = frozenset({KIND_SCHEDULED, KIND_CANCELLED, KIND_REJECTED})

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_DIGEST_LEN = len(_DIGEST_PREFIX) + 64


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class DelayQueueError(Exception):
    """Base class for all delay-queue errors."""


class BadTaskError(DelayQueueError):
    """task_id is not a non-empty str."""


class BadDigestError(DelayQueueError):
    """payload_digest is not a well-formed sha256: pin."""


class BadDelayError(DelayQueueError):
    """delay_seqs is not a positive int."""


class BadReasonError(DelayQueueError):
    """reason is not a str (or exceeds the length cap)."""


class DuplicateTaskError(DelayQueueError):
    """task_id is already booked (scheduled or retired)."""


class UnknownTaskError(DelayQueueError):
    """task_id is not in the ledger."""


class SeqOrderError(DelayQueueError):
    """Caller seq did not strictly increase."""


class AuditKindError(DelayQueueError):
    """Unknown audit kind for delay_queue_audit_event."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_task_id(task_id: Any) -> str:
    if isinstance(task_id, bool) or not isinstance(task_id, str):
        raise BadTaskError(
            f"task_id must be str, got {type(task_id).__name__}"
        )
    if not task_id.strip():
        raise BadTaskError("task_id must be non-empty")
    if len(task_id) > 256:
        raise BadTaskError("task_id exceeds 256 chars")
    return task_id


def _check_digest(digest: Any) -> str:
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadDigestError(
            f"payload_digest must be str, got {type(digest).__name__}"
        )
    if len(digest) != _DIGEST_LEN or not digest.startswith(_DIGEST_PREFIX):
        raise BadDigestError(
            "payload_digest must be 'sha256:' + 64 hex chars"
        )
    hexpart = digest[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError("payload_digest hex part is not lowercase hex")
    return digest


def _check_delay(delay_seqs: Any) -> int:
    if isinstance(delay_seqs, bool) or not isinstance(delay_seqs, int):
        raise BadDelayError(
            f"delay_seqs must be int, got {type(delay_seqs).__name__}"
        )
    if delay_seqs < 1:
        raise BadDelayError("delay_seqs must be positive")
    if delay_seqs > _MAX_INT:
        raise BadDelayError("delay_seqs exceeds safe range")
    return delay_seqs


def _check_reason(reason: Any) -> str:
    if isinstance(reason, bool) or not isinstance(reason, str):
        raise BadReasonError(
            f"reason must be str, got {type(reason).__name__}"
        )
    if len(reason) > 1024:
        raise BadReasonError("reason exceeds 1024 chars")
    return reason


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise DelayQueueError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise DelayQueueError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise DelayQueueError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([DELAY_QUEUE_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScheduleRecord:
    """Booked delayed task: becomes due at ``ready_at``.

    ``ready_at = seq + delay_seqs`` in caller logical time. The payload
    is pinned by digest only -- raw bytes never enter a record.
    """

    task_id: str
    payload_digest: str
    delay_seqs: int
    ready_at: int
    digest: str
    seq: int
    schema: str = DELAY_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "schedule",
                self.task_id,
                self.payload_digest,
                self.delay_seqs,
                self.ready_at,
                self.seq,
            )
        except DelayQueueError:
            return False
        return recomputed == self.digest and (
            self.schema == DELAY_QUEUE_SCHEMA
        )


@dataclass(frozen=True)
class CancelRecord:
    """Terminal removal of a scheduled task.

    The ``task_id`` is retired by this record and may never be
    re-scheduled -- a reappearing task is a new task with a new id.
    """

    task_id: str
    reason: str
    digest: str
    seq: int
    schema: str = DELAY_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "cancel", self.task_id, self.reason, self.seq
            )
        except DelayQueueError:
            return False
        return recomputed == self.digest and (
            self.schema == DELAY_QUEUE_SCHEMA
        )


@dataclass(frozen=True)
class PollReport:
    """Pure read view: which scheduled tasks are due at this seq.

    ``due`` holds task ids with ``ready_at <= seq``, sorted for
    determinism. Booking nothing -- the report is a view, not a claim.
    """

    seq: int
    due: Tuple[str, ...]
    schema: str = DELAY_QUEUE_SCHEMA


@dataclass(frozen=True)
class TaskView:
    """Pure read view of one scheduled task's delay state."""

    task_id: str
    payload_digest: str
    delay_seqs: int
    ready_at: int
    schema: str = DELAY_QUEUE_SCHEMA


@dataclass(frozen=True)
class QueueStats:
    """Pure read view of ledger-wide counters."""

    scheduled: int
    due: int
    cancelled: int
    schema: str = DELAY_QUEUE_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def delay_queue_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the delay queue.

    Raw payloads never cross the audit boundary: ``detail`` may carry
    digests, ids, delays, reasons and counts -- never ``payload``,
    ``payload_bytes`` or ``value``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"payload", "payload_bytes", "value", "raw"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": DELAY_QUEUE_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class DelayQueue:
    """Deterministic delay-queue bookkeeping (single-host).

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). Read views
    (``task``, ``poll``, ``pending``, ``due_ids``, ``stats``,
    ``audit_log``) are pure: seq shape is validated, never consumed.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._retired: set = set()
        self._scheduled: list = []
        self._cancelled: list = []
        self._audit: list = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not exceed last seq {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, task_id: str = "") -> Dict[str, Any]:
        row = delay_queue_audit_event(
            KIND_REJECTED, {"reason": reason, "task_id": task_id}, seq
        )
        self._audit.append(row)
        return row

    # -- pure views --------------------------------------------------------

    def task(self, task_id: str) -> Optional[TaskView]:
        """State of one scheduled task, or None if never scheduled."""
        task_id = _check_task_id(task_id)
        with self._lock:
            entry = self._entries.get(task_id)
            if entry is None:
                return None
            return TaskView(
                task_id=task_id,
                payload_digest=entry["payload_digest"],
                delay_seqs=entry["delay_seqs"],
                ready_at=entry["ready_at"],
            )

    def pending(self) -> Tuple[str, ...]:
        """Ids of tasks that are scheduled and not yet cancelled."""
        with self._lock:
            return tuple(sorted(self._entries.keys()))

    def due_ids(self, seq: int) -> Tuple[str, ...]:
        """Ids that are due at ``seq`` (``ready_at <= seq``), sorted."""
        _check_seq(seq)
        with self._lock:
            return tuple(
                sorted(
                    tid
                    for tid, e in self._entries.items()
                    if e["ready_at"] <= seq
                )
            )

    def poll(self, seq: int) -> PollReport:
        """Which scheduled tasks are due at ``seq``.

        Pure read view: validates seq shape, consumes nothing, writes
        no audit row. Due-ness is data -- delivery is the host's job.
        """
        _check_seq(seq)
        with self._lock:
            due = tuple(
                sorted(
                    tid
                    for tid, e in self._entries.items()
                    if e["ready_at"] <= seq
                )
            )
        return PollReport(seq=seq, due=due)

    def stats(self) -> QueueStats:
        with self._lock:
            return QueueStats(
                scheduled=len(self._scheduled),
                due=sum(
                    1 for e in self._entries.values()
                    if e["ready_at"] <= self._last_seq
                ),
                cancelled=len(self._cancelled),
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    # -- mutations ---------------------------------------------------------

    def schedule(
        self,
        task_id: str,
        payload_digest: str,
        delay_seqs: int,
        seq: int,
    ) -> ScheduleRecord:
        """Book a delayed task with ``ready_at = seq + delay_seqs``.

        Ids are never recycled: re-scheduling an active or retired id
        raises ``DuplicateTaskError`` fail-closed. Failed mutations
        consume their seq.
        """
        with self._lock:
            self._claim(seq)
            try:
                task_id = _check_task_id(task_id)
                payload_digest = _check_digest(payload_digest)
                delay_seqs = _check_delay(delay_seqs)
                if task_id in self._entries or task_id in self._retired:
                    raise DuplicateTaskError(
                        f"task_id already booked: {task_id}"
                    )
            except DelayQueueError as exc:
                self._reject(
                    seq,
                    type(exc).__name__,
                    task_id if isinstance(task_id, str) else "",
                )
                raise
            ready_at = seq + delay_seqs
            record = ScheduleRecord(
                task_id=task_id,
                payload_digest=payload_digest,
                delay_seqs=delay_seqs,
                ready_at=ready_at,
                digest=_pin(
                    "schedule",
                    task_id,
                    payload_digest,
                    delay_seqs,
                    ready_at,
                    seq,
                ),
                seq=seq,
            )
            self._entries[task_id] = {
                "payload_digest": payload_digest,
                "delay_seqs": delay_seqs,
                "ready_at": ready_at,
            }
            self._scheduled.append(record)
            self._audit.append(
                delay_queue_audit_event(
                    KIND_SCHEDULED,
                    {
                        "task_id": task_id,
                        "payload_digest": payload_digest,
                        "delay_seqs": delay_seqs,
                        "ready_at": ready_at,
                    },
                    seq,
                )
            )
            return record

    def cancel(
        self, task_id: str, seq: int, reason: str = ""
    ) -> CancelRecord:
        """Terminally remove a scheduled task.

        Retires the id: it may never be re-scheduled. Unknown ids fail
        closed with ``UnknownTaskError``.
        """
        with self._lock:
            self._claim(seq)
            try:
                task_id = _check_task_id(task_id)
                reason = _check_reason(reason)
                entry = self._entries.get(task_id)
                if entry is None:
                    raise UnknownTaskError(
                        f"unknown task_id: {task_id}"
                    )
            except DelayQueueError as exc:
                self._reject(
                    seq,
                    type(exc).__name__,
                    task_id if isinstance(task_id, str) else "",
                )
                raise
            record = CancelRecord(
                task_id=task_id,
                reason=reason,
                digest=_pin("cancel", task_id, reason, seq),
                seq=seq,
            )
            del self._entries[task_id]
            self._retired.add(task_id)
            self._cancelled.append(record)
            self._audit.append(
                delay_queue_audit_event(
                    KIND_CANCELLED,
                    {"task_id": task_id, "reason": reason},
                    seq,
                )
            )
            return record


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: schedule, poll due, cancel."""
    dq = DelayQueue()
    digest = "sha256:" + "ab" * 32
    rec = dq.schedule("t-1", digest, 5, 1)
    assert rec.verify() and rec.ready_at == 6
    dq.schedule("t-2", digest, 10, 2)
    assert dq.poll(3).due == ()
    report = dq.poll(6)
    assert report.due == ("t-1",), report.due
    cancelled = dq.cancel("t-2", 7, "superseded")
    assert cancelled.verify()
    assert dq.pending() == ("t-1",)
    assert dq.poll(100).due == ("t-1",)
    try:
        dq.schedule("t-2", digest, 1, 8)
        raise AssertionError("expected DuplicateTaskError")
    except DuplicateTaskError:
        pass
    stats = dq.stats()
    assert (stats.scheduled, stats.cancelled) == (2, 1)
    print("delay-queue OK: schedule, poll due, cancel, pins, audit")


if __name__ == "__main__":
    main()
