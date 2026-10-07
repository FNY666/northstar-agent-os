"""Job queue: Celery/Sidekiq-shaped background-job lifecycle bookkeeping.

Research motivation: Celery (Python) and Sidekiq (Ruby) move background
work through named queues with at-least-once delivery: a producer
enqueues a job, a worker reserves it (making it invisible while work
runs), then acknowledges success or retries with a backoff. A job whose
retry budget is exhausted is dead-lettered. This module books that
lifecycle deterministically. It executes no job, runs no worker, and
measures no time -- the host owns the workers, the backoff policy, and
the actual reprocessing.

Public API:

- ``JobQueue()`` -- mutable, RLock-guarded ledger.
  - ``enqueue(job_id, queue, task, payload_digest, seq, priority=0,
    max_retries=3, delay_seqs=0)`` -> frozen ``EnqueueRecord``: books a
    job into a named queue (``ready``). Ids are caller-chosen and never
    recycled: duplicates raise ``DuplicateJobError`` fail-closed.
  - ``dequeue(worker_id, queue, seq)`` -> ``Optional[DequeuedJob]``:
    reserves the highest-priority ready job whose backoff has elapsed
    (priority desc, then FIFO); the job becomes invisible
    (``reserved``) until it is acked or retried. Empty queue is
    ``None`` as data, never raised.
  - ``ack(job_id, seq)`` -> frozen ``AckRecord``: terminal success.
  - ``retry(job_id, seq, delay_seqs=0)`` -> frozen ``RetryRecord``:
    returns a reserved job to ``ready`` with a logical-seq backoff
    (``not_before_seq = seq + delay_seqs``). When the just-completed
    attempt already reached ``max_retries`` the job is marked
    ``dead`` and ``MaxRetriesExceededError`` is raised fail-closed --
    from then on nothing may act on it.
  - ``job(job_id)`` / ``ready(queue)`` / ``reserved()`` / ``stats()`` /
    ``audit_log()`` -- pure read views; consume no seq.
- ``job_queue_audit_event(kind, detail, seq)`` -- ``audit.ndjson/1``
  records: ``"job.enqueued"``, ``"job.dequeued"``, ``"job.acked"``,
  ``"job.retried"``, ``"job.dead"``, ``"job.rejected"``.

Backoff and delay are logical seqs (``seq + delay_seqs``), never wall
clock: a job is eligible for dequeue only when the caller's seq has
reached ``not_before_seq``. Attempts are counted on reservation
(dequeue) -- every execution the host runs is booked as data.

Payloads are pinned by ``sha256:`` digest only -- raw bytes never enter
a record or cross the audit boundary. Worker ids, queue names and task
names are host-declared data; the module cannot prove a booked
reservation was actually executed by the named worker.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* enqueues, reservations, acks and
  retries; it runs no worker, owns no timer, and cannot prove a job
  was actually executed.
- A ``DequeuedJob`` is a reservation decision, not proof of delivery:
  the job completes only if the host acts on it.
- ``dead`` is terminal bookkeeping, not an automatic transfer: the
  host must move the record to its own dead-letter storage.
- Priority orders dequeue preference only; it makes no preemption or
  fairness guarantee across queues.

Version pin: ``job-queue.v1`` / schema pin ``northstar.job-queue.v1``.
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
JOB_QUEUE_VERSION = "job-queue.v1"

#: Schema pin carried by records and audit events.
JOB_QUEUE_SCHEMA = "northstar.job-queue.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_ENQUEUED = "job.enqueued"
KIND_DEQUEUED = "job.dequeued"
KIND_ACKED = "job.acked"
KIND_RETRIED = "job.retried"
KIND_DEAD = "job.dead"
KIND_REJECTED = "job.rejected"
_KINDS = frozenset(
    {
        KIND_ENQUEUED,
        KIND_DEQUEUED,
        KIND_ACKED,
        KIND_RETRIED,
        KIND_DEAD,
        KIND_REJECTED,
    }
)

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_DIGEST_LEN = len(_DIGEST_PREFIX) + 64

#: Job lifecycle states.
_STATE_READY = "ready"
_STATE_RESERVED = "reserved"
_STATE_DONE = "done"
_STATE_DEAD = "dead"

#: Priority bounds (Sidekiq weights are per-queue; this is per-job).
_PRIORITY_MIN = -100
_PRIORITY_MAX = 100

#: max_retries bounds.
_MAX_RETRIES_CAP = 64


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class JobQueueError(Exception):
    """Base class for all job-queue errors."""


class BadJobError(JobQueueError):
    """job_id is not a non-empty str."""


class DuplicateJobError(JobQueueError):
    """job_id is already booked (any state)."""


class UnknownJobError(JobQueueError):
    """job_id is not in the ledger."""


class BadQueueError(JobQueueError):
    """queue name is not a non-empty str."""


class UnknownQueueError(JobQueueError):
    """queue name has never been seen (for dequeue)."""


class BadWorkerError(JobQueueError):
    """worker_id is not a non-empty str."""


class BadTaskError(JobQueueError):
    """task name is not a non-empty str."""


class BadDigestError(JobQueueError):
    """payload_digest is not a well-formed sha256: pin."""


class BadPriorityError(JobQueueError):
    """priority is not an int in [-100, 100]."""


class BadRetryError(JobQueueError):
    """max_retries is not an int in [1, 64]."""


class BadDelayError(JobQueueError):
    """delay_seqs is not a non-negative int."""


class JobStateError(JobQueueError):
    """The job is not in the state the operation requires."""


class MaxRetriesExceededError(JobQueueError):
    """The retry would exceed the job's max_retries budget."""


class SeqOrderError(JobQueueError):
    """Caller seq did not strictly increase."""


class AuditKindError(JobQueueError):
    """Unknown audit kind for job_queue_audit_event."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_job_id(job_id: Any) -> str:
    if isinstance(job_id, bool) or not isinstance(job_id, str):
        raise BadJobError(
            f"job_id must be str, got {type(job_id).__name__}"
        )
    if not job_id.strip():
        raise BadJobError("job_id must be non-empty")
    if len(job_id) > 256:
        raise BadJobError("job_id exceeds 256 chars")
    return job_id


def _check_queue(queue: Any) -> str:
    if isinstance(queue, bool) or not isinstance(queue, str):
        raise BadQueueError(
            f"queue must be str, got {type(queue).__name__}"
        )
    if not queue.strip():
        raise BadQueueError("queue must be non-empty")
    if len(queue) > 128:
        raise BadQueueError("queue exceeds 128 chars")
    return queue


def _check_worker(worker_id: Any) -> str:
    if isinstance(worker_id, bool) or not isinstance(worker_id, str):
        raise BadWorkerError(
            f"worker_id must be str, got {type(worker_id).__name__}"
        )
    if not worker_id.strip():
        raise BadWorkerError("worker_id must be non-empty")
    if len(worker_id) > 256:
        raise BadWorkerError("worker_id exceeds 256 chars")
    return worker_id


def _check_task(task: Any) -> str:
    if isinstance(task, bool) or not isinstance(task, str):
        raise BadTaskError(
            f"task must be str, got {type(task).__name__}"
        )
    if not task.strip():
        raise BadTaskError("task must be non-empty")
    if len(task) > 256:
        raise BadTaskError("task exceeds 256 chars")
    return task


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


def _check_priority(priority: Any) -> int:
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise BadPriorityError(
            f"priority must be int, got {type(priority).__name__}"
        )
    if priority < _PRIORITY_MIN or priority > _PRIORITY_MAX:
        raise BadPriorityError(
            f"priority must be in [{_PRIORITY_MIN}, {_PRIORITY_MAX}]"
        )
    return priority


def _check_max_retries(max_retries: Any) -> int:
    if isinstance(max_retries, bool) or not isinstance(max_retries, int):
        raise BadRetryError(
            f"max_retries must be int, got {type(max_retries).__name__}"
        )
    if max_retries < 1 or max_retries > _MAX_RETRIES_CAP:
        raise BadRetryError(
            f"max_retries must be in [1, {_MAX_RETRIES_CAP}]"
        )
    return max_retries


def _check_delay(delay_seqs: Any) -> int:
    if isinstance(delay_seqs, bool) or not isinstance(delay_seqs, int):
        raise BadDelayError(
            f"delay_seqs must be int, got {type(delay_seqs).__name__}"
        )
    if delay_seqs < 0:
        raise BadDelayError("delay_seqs must be non-negative")
    if delay_seqs > _MAX_INT:
        raise BadDelayError("delay_seqs exceeds safe range")
    return delay_seqs


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
                raise JobQueueError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise JobQueueError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise JobQueueError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([JOB_QUEUE_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnqueueRecord:
    """Booked arrival of a job in a named queue.

    ``delay_seqs`` defers first eligibility: the job is ready for
    dequeue only when the caller's seq reaches ``seq + delay_seqs``.
    The payload is pinned by digest only -- raw bytes never enter a
    record.
    """

    job_id: str
    queue: str
    task: str
    payload_digest: str
    priority: int
    max_retries: int
    delay_seqs: int
    digest: str
    seq: int
    schema: str = JOB_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "enqueue",
                self.job_id,
                self.queue,
                self.task,
                self.payload_digest,
                self.priority,
                self.max_retries,
                self.delay_seqs,
                self.seq,
            )
        except JobQueueError:
            return False
        return recomputed == self.digest and (
            self.schema == JOB_QUEUE_SCHEMA
        )


@dataclass(frozen=True)
class DequeuedJob:
    """Booked reservation of a ready job by a worker.

    The job is invisible to other workers until it is acked or
    retried. ``attempts`` counts this execution (first dequeue is
    attempt 1). A reservation decision, not proof of execution.
    """

    job_id: str
    queue: str
    task: str
    payload_digest: str
    worker_id: str
    attempts: int
    priority: int
    digest: str
    seq: int
    schema: str = JOB_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "dequeue",
                self.job_id,
                self.queue,
                self.task,
                self.payload_digest,
                self.worker_id,
                self.attempts,
                self.priority,
                self.seq,
            )
        except JobQueueError:
            return False
        return recomputed == self.digest and (
            self.schema == JOB_QUEUE_SCHEMA
        )


@dataclass(frozen=True)
class AckRecord:
    """Terminal success of a reserved job."""

    job_id: str
    attempts: int
    digest: str
    seq: int
    schema: str = JOB_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin("ack", self.job_id, self.attempts, self.seq)
        except JobQueueError:
            return False
        return recomputed == self.digest and (
            self.schema == JOB_QUEUE_SCHEMA
        )


@dataclass(frozen=True)
class RetryRecord:
    """Booked decision to return a reserved job to ``ready``.

    ``attempts`` is the count of the execution that just failed
    (booked at dequeue time -- retry does not increment it). A retry
    that would grant an execution beyond ``max_retries`` instead marks
    the job ``dead``: ``state`` is ``"ready"`` normally and ``"dead"``
    in that terminal case, where ``MaxRetriesExceededError`` is raised
    fail-closed.
    """

    job_id: str
    attempts: int
    delay_seqs: int
    max_retries: int
    state: str
    digest: str
    seq: int
    schema: str = JOB_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "retry",
                self.job_id,
                self.attempts,
                self.delay_seqs,
                self.max_retries,
                self.state,
                self.seq,
            )
        except JobQueueError:
            return False
        return recomputed == self.digest and (
            self.schema == JOB_QUEUE_SCHEMA
        )


@dataclass(frozen=True)
class JobView:
    """Pure read view of one job's ledger state."""

    job_id: str
    queue: str
    task: str
    payload_digest: str
    priority: int
    attempts: int
    max_retries: int
    state: str
    worker_id: str
    not_before_seq: int
    schema: str = JOB_QUEUE_SCHEMA


@dataclass(frozen=True)
class QueueStats:
    """Pure read view of ledger-wide counters."""

    ready: int
    reserved: int
    done: int
    dead: int
    enqueued: int
    dequeued: int
    queues: int
    schema: str = JOB_QUEUE_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def job_queue_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the job queue.

    Raw payloads never cross the audit boundary: ``detail`` may carry
    ids, queue names, task names, worker ids, attempts and counts --
    never ``payload`` or ``payload_bytes``.
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
        "module": JOB_QUEUE_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class JobQueue:
    """Deterministic Celery/Sidekiq-shaped job queue bookkeeping.

    All mutations take a caller-supplied strictly increasing ``seq``
    (logical time); no wall clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position). ``dequeue`` on an
    empty queue returns ``None`` as data -- emptiness is not a failure.
    Read views (``job``, ``ready``, ``reserved``, ``stats``,
    ``audit_log``) are pure: seq shape is validated, never consumed.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._known_queues: set = set()
        self._enqueues: list = []
        self._dequeues: list = []
        self._acks: list = []
        self._retries: list = []
        self._dead: int = 0
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

    def _reject(self, seq: int, reason: str, job_id: str = "") -> Dict[str, Any]:
        row = job_queue_audit_event(
            KIND_REJECTED, {"reason": reason, "job_id": job_id}, seq
        )
        self._audit.append(row)
        return row

    # -- pure views --------------------------------------------------------

    def job(self, job_id: str) -> Optional[JobView]:
        """State of one job, or None if never enqueued."""
        job_id = _check_job_id(job_id)
        with self._lock:
            entry = self._entries.get(job_id)
            if entry is None:
                return None
            return JobView(
                job_id=job_id,
                queue=entry["queue"],
                task=entry["task"],
                payload_digest=entry["payload_digest"],
                priority=entry["priority"],
                attempts=entry["attempts"],
                max_retries=entry["max_retries"],
                state=entry["state"],
                worker_id=entry["worker_id"],
                not_before_seq=entry["not_before_seq"],
            )

    def ready(self, queue: str) -> Tuple[str, ...]:
        """Ids of ready jobs in one queue, dequeue-order."""
        queue = _check_queue(queue)
        with self._lock:
            return tuple(self._ordered_ready(queue, None))

    def reserved(self) -> Tuple[str, ...]:
        """Ids of currently reserved jobs."""
        with self._lock:
            return tuple(
                sorted(
                    jid
                    for jid, e in self._entries.items()
                    if e["state"] == _STATE_RESERVED
                )
            )

    def stats(self) -> QueueStats:
        with self._lock:
            ready = sum(
                1 for e in self._entries.values()
                if e["state"] == _STATE_READY
            )
            reserved = sum(
                1 for e in self._entries.values()
                if e["state"] == _STATE_RESERVED
            )
            done = sum(
                1 for e in self._entries.values()
                if e["state"] == _STATE_DONE
            )
            dead = sum(
                1 for e in self._entries.values()
                if e["state"] == _STATE_DEAD
            )
            return QueueStats(
                ready=ready,
                reserved=reserved,
                done=done,
                dead=dead,
                enqueued=len(self._enqueues),
                dequeued=len(self._dequeues),
                queues=len(self._known_queues),
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    # -- ordering ----------------------------------------------------------

    def _ordered_ready(self, queue: str, seq: Optional[int]) -> list:
        """Ready jobs in ``queue``: priority desc, FIFO.

        When ``seq`` is not None, only jobs whose backoff has elapsed
        (``not_before_seq <= seq``) are eligible; ``None`` lists all
        ready jobs regardless of backoff.
        """
        eligible = [
            (jid, e)
            for jid, e in self._entries.items()
            if e["queue"] == queue
            and e["state"] == _STATE_READY
            and (seq is None or e["not_before_seq"] <= seq)
        ]
        eligible.sort(
            key=lambda pair: (-pair[1]["priority"], pair[1]["enqueue_seq"])
        )
        return [jid for jid, _ in eligible]

    # -- mutations ---------------------------------------------------------

    def enqueue(
        self,
        job_id: str,
        queue: str,
        task: str,
        payload_digest: str,
        seq: int,
        priority: int = 0,
        max_retries: int = 3,
        delay_seqs: int = 0,
    ) -> EnqueueRecord:
        """Book a job into a named queue.

        Ids are caller-chosen and never recycled: any re-enqueue of a
        booked id raises ``DuplicateJobError`` fail-closed. ``delay_seqs``
        defers first dequeue eligibility to ``seq + delay_seqs``
        (logical-seq countdown). Failed mutations consume their seq.
        """
        with self._lock:
            self._claim(seq)
            try:
                job_id = _check_job_id(job_id)
                queue = _check_queue(queue)
                task = _check_task(task)
                payload_digest = _check_digest(payload_digest)
                priority = _check_priority(priority)
                max_retries = _check_max_retries(max_retries)
                delay_seqs = _check_delay(delay_seqs)
                if job_id in self._entries:
                    raise DuplicateJobError(
                        f"job_id already booked: {job_id}"
                    )
            except JobQueueError as exc:
                self._reject(
                    seq,
                    type(exc).__name__,
                    job_id if isinstance(job_id, str) else "",
                )
                raise
            record = EnqueueRecord(
                job_id=job_id,
                queue=queue,
                task=task,
                payload_digest=payload_digest,
                priority=priority,
                max_retries=max_retries,
                delay_seqs=delay_seqs,
                digest=_pin(
                    "enqueue",
                    job_id,
                    queue,
                    task,
                    payload_digest,
                    priority,
                    max_retries,
                    delay_seqs,
                    seq,
                ),
                seq=seq,
            )
            self._entries[job_id] = {
                "queue": queue,
                "task": task,
                "payload_digest": payload_digest,
                "priority": priority,
                "attempts": 0,
                "max_retries": max_retries,
                "state": _STATE_READY,
                "worker_id": "",
                "not_before_seq": seq + delay_seqs,
                "enqueue_seq": seq,
            }
            self._known_queues.add(queue)
            self._enqueues.append(record)
            self._audit.append(
                job_queue_audit_event(
                    KIND_ENQUEUED,
                    {
                        "job_id": job_id,
                        "queue": queue,
                        "task": task,
                        "priority": priority,
                        "max_retries": max_retries,
                        "delay_seqs": delay_seqs,
                    },
                    seq,
                )
            )
            return record

    def dequeue(
        self, worker_id: str, queue: str, seq: int
    ) -> Optional[DequeuedJob]:
        """Reserve the next eligible job in ``queue`` for a worker.

        Order: priority desc, then FIFO by enqueue seq. Eligibility
        requires ``not_before_seq <= seq`` (logical-seq backoff). The
        job becomes ``reserved`` (invisible) and ``attempts`` increments
        as data. An empty queue or no eligible job returns ``None`` as
        data -- emptiness is not a failure. Unknown queues fail closed.
        """
        with self._lock:
            self._claim(seq)
            try:
                worker_id = _check_worker(worker_id)
                queue = _check_queue(queue)
                if queue not in self._known_queues:
                    raise UnknownQueueError(
                        f"unknown queue: {queue}"
                    )
            except JobQueueError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            eligible = self._ordered_ready(queue, seq)
            if not eligible:
                return None
            job_id = eligible[0]
            entry = self._entries[job_id]
            entry["state"] = _STATE_RESERVED
            entry["worker_id"] = worker_id
            entry["attempts"] += 1
            record = DequeuedJob(
                job_id=job_id,
                queue=queue,
                task=entry["task"],
                payload_digest=entry["payload_digest"],
                worker_id=worker_id,
                attempts=entry["attempts"],
                priority=entry["priority"],
                digest=_pin(
                    "dequeue",
                    job_id,
                    queue,
                    entry["task"],
                    entry["payload_digest"],
                    worker_id,
                    entry["attempts"],
                    entry["priority"],
                    seq,
                ),
                seq=seq,
            )
            self._dequeues.append(record)
            self._audit.append(
                job_queue_audit_event(
                    KIND_DEQUEUED,
                    {
                        "job_id": job_id,
                        "queue": queue,
                        "worker_id": worker_id,
                        "attempts": entry["attempts"],
                    },
                    seq,
                )
            )
            return record

    def ack(self, job_id: str, seq: int) -> AckRecord:
        """Terminal success of a reserved job.

        Only ``reserved`` jobs may be acked; anything else raises
        ``JobStateError`` (unknown ids raise ``UnknownJobError``)
        fail-closed.
        """
        with self._lock:
            self._claim(seq)
            try:
                job_id = _check_job_id(job_id)
                entry = self._entries.get(job_id)
                if entry is None:
                    raise UnknownJobError(f"unknown job_id: {job_id}")
                if entry["state"] != _STATE_RESERVED:
                    raise JobStateError(
                        f"job {job_id} is {entry['state']}, "
                        "only reserved jobs may be acked"
                    )
            except JobQueueError as exc:
                self._reject(seq, type(exc).__name__, job_id)
                raise
            record = AckRecord(
                job_id=job_id,
                attempts=entry["attempts"],
                digest=_pin("ack", job_id, entry["attempts"], seq),
                seq=seq,
            )
            entry["state"] = _STATE_DONE
            entry["worker_id"] = ""
            self._acks.append(record)
            self._audit.append(
                job_queue_audit_event(
                    KIND_ACKED,
                    {"job_id": job_id, "attempts": entry["attempts"]},
                    seq,
                )
            )
            return record

    def retry(
        self, job_id: str, seq: int, delay_seqs: int = 0
    ) -> RetryRecord:
        """Return a reserved job to ``ready`` with a backoff.

        ``attempts`` is not incremented here: it counts executions and
        was already booked by ``dequeue()``. The job becomes eligible
        again at ``seq + delay_seqs`` (exponential backoff is the
        host's policy -- this ledger only books the delay). When the
        just-completed attempt already reached ``max_retries`` the job
        is marked ``dead`` and ``MaxRetriesExceededError`` is raised
        fail-closed; a dead job is terminal. Only ``reserved`` jobs
        may be retried.
        """
        with self._lock:
            self._claim(seq)
            try:
                job_id = _check_job_id(job_id)
                delay_seqs = _check_delay(delay_seqs)
                entry = self._entries.get(job_id)
                if entry is None:
                    raise UnknownJobError(f"unknown job_id: {job_id}")
                if entry["state"] != _STATE_RESERVED:
                    raise JobStateError(
                        f"job {job_id} is {entry['state']}, "
                        "only reserved jobs may be retried"
                    )
                if entry["attempts"] >= entry["max_retries"]:
                    entry["state"] = _STATE_DEAD
                    entry["worker_id"] = ""
                    dead_record = RetryRecord(
                        job_id=job_id,
                        attempts=entry["attempts"],
                        delay_seqs=delay_seqs,
                        max_retries=entry["max_retries"],
                        state=_STATE_DEAD,
                        digest=_pin(
                            "retry",
                            job_id,
                            entry["attempts"],
                            delay_seqs,
                            entry["max_retries"],
                            _STATE_DEAD,
                            seq,
                        ),
                        seq=seq,
                    )
                    self._retries.append(dead_record)
                    self._dead += 1
                    self._audit.append(
                        job_queue_audit_event(
                            KIND_DEAD,
                            {
                                "job_id": job_id,
                                "attempts": entry["attempts"],
                                "max_retries": entry["max_retries"],
                            },
                            seq,
                        )
                    )
                    raise MaxRetriesExceededError(
                        f"max_retries={entry['max_retries']} exceeded "
                        f"for {job_id}"
                    )
            except JobQueueError as exc:
                self._reject(seq, type(exc).__name__, job_id)
                raise
            record = RetryRecord(
                job_id=job_id,
                attempts=entry["attempts"],
                delay_seqs=delay_seqs,
                max_retries=entry["max_retries"],
                state=_STATE_READY,
                digest=_pin(
                    "retry",
                    job_id,
                    entry["attempts"],
                    delay_seqs,
                    entry["max_retries"],
                    _STATE_READY,
                    seq,
                ),
                seq=seq,
            )
            entry["state"] = _STATE_READY
            entry["worker_id"] = ""
            entry["not_before_seq"] = seq + delay_seqs
            self._retries.append(record)
            self._audit.append(
                job_queue_audit_event(
                    KIND_RETRIED,
                    {
                        "job_id": job_id,
                        "attempts": entry["attempts"],
                        "delay_seqs": delay_seqs,
                    },
                    seq,
                )
            )
            return record


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: enqueue, priority dequeue, ack, retry,
    delay backoff, dead-lettering."""
    jq = JobQueue()
    lo = "sha256:" + "aa" * 32
    hi = "sha256:" + "bb" * 32

    rec_lo = jq.enqueue("j-low", "default", "send_email", lo, 1,
                        priority=-1)
    rec_hi = jq.enqueue("j-high", "default", "send_email", hi, 2,
                        priority=10)
    assert rec_lo.verify() and rec_hi.verify()
    assert jq.ready("default") == ("j-high", "j-low")

    got = jq.dequeue("w-1", "default", 3)
    assert got is not None and got.job_id == "j-high"
    assert got.attempts == 1 and got.verify()
    assert jq.reserved() == ("j-high",)

    # None left eligible after one reservation; empty is data.
    got2 = jq.dequeue("w-2", "default", 4)
    assert got2 is not None and got2.job_id == "j-low"
    assert jq.dequeue("w-1", "default", 5) is None

    # Retry with backoff: not eligible until seq catches up.
    r = jq.retry("j-low", 6, delay_seqs=10)
    assert r.verify() and r.state == "ready" and r.attempts == 1
    assert jq.job("j-low") is not None
    assert jq.job("j-low").not_before_seq == 16
    assert jq.dequeue("w-1", "default", 7) is None
    got3 = jq.dequeue("w-1", "default", 16)
    assert got3 is not None and got3.job_id == "j-low"
    assert got3.attempts == 2

    # Retry budget of 1: second retry kills the job.
    jq2 = JobQueue()
    jq2.enqueue("j-1", "critical", "charge", lo, 1, max_retries=1)
    d = jq2.dequeue("w-9", "critical", 2)
    assert d is not None
    try:
        jq2.retry("j-1", 3)
        raise AssertionError("expected MaxRetriesExceededError")
    except MaxRetriesExceededError:
        pass
    assert jq2.job("j-1").state == "dead"

    # Ack the high-priority job.
    a = jq.ack("j-high", 17)
    assert a.verify() and jq.job("j-high").state == "done"

    stats = jq.stats()
    assert (stats.enqueued, stats.dequeued, stats.queues) == (2, 3, 1)
    print("job-queue OK: enqueue, priority, dequeue, ack, retry, delay, dead")


if __name__ == "__main__":
    main()
