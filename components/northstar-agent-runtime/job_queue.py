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
    ``None`` as data, never raised.  A recorded refusal covering a
    candidate's action **skips** that candidate -- a refusal is scoped
    to one (job, action) pair, so it must not deny the queue to every
    other job -- and when every candidate is refused the call raises
    the gate's own refusal error and hands nothing out.  Every refused
    candidate books its own ``job.rejected`` row, naming the job, the
    action and the hold's reason slug, so the trail says which
    candidates were refused rather than only that some were.
  - ``ack(job_id, seq)`` -> frozen ``AckRecord``: terminal success.
  - ``dead(job_id, seq)`` -> frozen ``DeadRecord``: terminal **failure**.
    The job is withdrawn and never handed out again.  A recorded
    refusal does not block this: a refusal is about the *re-dispatch*,
    and a job being killed is not being offered again.
  - ``retry(job_id, seq, delay_seqs=0)`` -> frozen ``RetryRecord``:
    returns a reserved job to ``ready`` with a logical-seq backoff
    (``not_before_seq = seq + delay_seqs``). When the just-completed
    attempt already reached ``max_retries`` the job is marked
    ``dead`` and ``MaxRetriesExceededError`` is raised fail-closed --
    from then on nothing may act on it.  A refusal blocks the
    re-dispatch, and the refusal is booked in the trail as a
    ``job.rejected`` row naming the job, the action and the hold's
    reason slug -- on both the raising and the batch form.
  - ``retry_allowed(job_id, seq, delay_seqs=0)`` -> ``Optional[RetryRecord]``:
    the **batch-safe** form of ``retry``.  It returns ``None`` for
    "not re-dispatched" (a refused job, a job that is not reserved, an
    unknown job, a spent retry budget) instead of raising, so one
    refused job cannot abandon a sweep.  The gate is consulted once
    per job, whichever form is used.
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


class UnnamedRefusalError(JobQueueError):
    """The refusal gate refused without saying WHY.

    The gate's **boolean** form answers "not allowed" for two different
    things: a recorded refusal, and a gate that cannot answer at all
    (the hold fails closed, so both are ``False``).  The boolean form
    therefore carries no reason, and the batch form had nothing to put
    in the trail's ``reason`` slot -- it put the class name of the
    *missing* exception there, and the row read ``"NoneType"``.

    This error is what the queue raises **internally** for that case,
    so the row always names a real class.  It is not the host's error
    and it never escapes this module: the batch form turns it into
    ``None``, like every other refusal.
    """


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
    if seq > _MAX_INT:
        # A seq above the safe range cannot be PINNED by a digest.
        #
        # ``canonical_json`` serializes an integer outside the safe
        # range as an IEEE-754 double (RFC 8785 Appendix B note (2)),
        # so 2**53 and 2**53+1 canonicalize to the SAME bytes:
        #
        #     jcs_dumps([2**53])   == b'[9007199254740992]'
        #     jcs_dumps([2**53+1]) == b'[9007199254740992]'
        #
        # So a record's digest would stop pinning its seq, and a
        # *tampered* seq would still verify -- measured on a real
        # ``DequeuedJob``: the seq was changed from 9007199254740992 to
        # 9007199254740993, the digest was unchanged, and
        # ``verify()`` said True.
        #
        # The stdlib fallback refuses such an integer outright, so
        # without this bound the two configurations also disagreed
        # about whether a large seq is legal at all.
        #
        # The bound matches the repo's house pattern: see
        # ``grant_pin_ledger.py`` (``_MAX_COUNTER = 2**53 - 1``) and
        # ``profiler.py`` (``record_digest()`` refuses a huge integral
        # fail-closed).  ``seq`` was the one integer in a digest here
        # that was unbounded.
        raise SeqOrderError("seq exceeds the safe range")
    return seq


#: The hold's ``blocked_*`` reasons that are a property of the GATE, not
#: of the (job, action) pair being asked about.  A gate in one of these
#: states could not answer at all, so it refuses nothing in particular:
#: it is not skipped, and it books no row.  See :func:`_is_refusal`.
_GATE_CONDITION_REASONS = frozenset(
    {
        "blocked_store_unreadable",
        "blocked_row_invalid",
        "blocked_row_tampered",
    }
)


def _is_refusal(exc: BaseException) -> bool:
    """Is this exception a **per-job refusal**, rather than a broken gate?

    The queue side skips a refused candidate and asks about the next one.
    That is only sound when the exception means "this (job, action) pair
    is refused" -- and NOT when it means "the gate could not answer at
    all".  A broken gate is a property of the **gate**, not of the job,
    so it must not be skipped: skipping it would turn a broken gate into a
    silently degraded queue, which is fail-OPEN.

    The distinction is drawn on the error's own vocabulary, and it is
    duck-typed on purpose: the gate is supplied by the host, and this
    module does not import the wiring (the wiring imports the hold, and
    the hold must not drag the queue in).

    Two shapes count as a refusal:

    * the error carries a ``reason`` attribute whose value is one of the
      hold's **per-job** refusal reasons -- the wiring's
      ``RefusalRefusedError`` carries exactly that;
    * the error's class name is ``RefusalRefusedError`` -- the shape a
      host that re-implements the gate's contract uses.

    Everything else -- including a ``RuntimeError`` from a broken gate,
    and the ``TypeError`` this module raises for an unusable gate -- is
    NOT a refusal, and is not skipped.

    The one exception is this module's OWN
    :class:`UnnamedRefusalError`: that is a refusal the queue raised
    itself, because the gate's boolean form refused without saying
    why.  It is a refusal (the gate said "not allowed"), and it is
    named here so the trail can book it -- with a real class name.

    **A ``blocked_*`` prefix is NOT enough.**  The hold's own taxonomy
    mixes two different things under that prefix:

    * ``blocked_by_refusal`` -- a refusal ROW covers this (job, action)
      pair.  PER-JOB: skip it and ask about the next one.
    * ``blocked_key_invalid`` -- THIS (job, action) pair's identity is
      malformed, so it is refused.  PER-JOB: the identity names exactly
      one pair, and a different pair with a well-formed identity is
      unaffected.
    * ``blocked_store_unreadable`` -- the GATE could not read its own
      store.  A property of the GATE.
    * ``blocked_row_invalid`` -- the row on the key is not a refusal row
      at all, so the gate cannot establish that a refusal covers this
      action.  A property of the GATE.
    * ``blocked_row_tampered`` -- the row was forged.  A property of the
      GATE.

    The last three are the GATE's condition, and the design doc states
    twice what they mean: "A broken gate is NOT a refusal, and is not
    skipped" and "A broken gate books no row."  Skipping them would turn
    a broken gate into a silently degraded queue -- fail-OPEN -- and
    booking them would put a refusal in the trail that never happened.

    The real gate reports its own brokenness AS one of those reasons, so
    the prefix test could not tell the two apart.  Measured 2026-11-25,
    before this fix, with the real gate over a store that could not be
    read:

        dequeue raised: RefusalRefusedError (blocked_store_unreadable)
        job.rejected rows: 2

    -- two refusals booked for a gate that refused nothing in
    particular.  And with the gate breaking MID-LIST (candidate 1
    refused for real, candidate 2 hits the broken store), the broken
    answer was skipped like a refusal and the walk continued, so the
    queue could hand out a job behind a broken gate.
    """
    if isinstance(exc, UnnamedRefusalError):
        return True
    reason = getattr(exc, "reason", None)
    if isinstance(reason, str) and reason.startswith("blocked_"):
        if reason in _GATE_CONDITION_REASONS:
            return False
        return True
    return type(exc).__name__ == "RefusalRefusedError"


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        try:
            return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
        except ValueError as exc:
            # The sibling helper refuses input it cannot canonicalize
            # (a lone surrogate, a non-finite float, an unsupported
            # type) with ITS OWN error type -- ``JcsError``, which is
            # a ``ValueError``.  That type is not part of this
            # module's taxonomy, and it must not escape: every caller
            # here catches ``JobQueueError``, and the stdlib fallback
            # below raises exactly that.
            #
            # Left untranslated, the two configurations disagreed about
            # the SAME input -- the shipped path raised ``JcsError``,
            # the fallback raised ``JobQueueError`` -- and the shipped
            # path's error escaped the ``except JobQueueError`` clause
            # that was written to catch it.  Two consequences, both
            # measured:
            #
            # * ``verify()`` RAISED instead of answering ``False``, so
            #   a caller asking "is this record intact?" got an
            #   exception; and because ``JcsError`` is a
            #   ``ValueError``, a caller guarding with ``except
            #   ValueError`` treats a *tampered record* as a *parse
            #   error* and moves on -- the record is neither verified
            #   nor rejected.
            # * A refused ``enqueue()`` booked NO ``job.rejected``
            #   row, so the trail could not tell "the queue refused
            #   this job" from "the queue never saw it".
            raise JobQueueError(
                f"unencodable payload: {exc}"
            ) from exc

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
class DeadRecord:
    """Terminal failure of a reserved job.

    A job that fails terminally is **not** re-dispatched: it goes to
    ``dead``, which no ``dequeue`` will ever hand out.  This is the
    ledger's own terminal-failure operation, as distinct from
    ``retry`` -- which is a failure that will be re-dispatched -- and
    from ``ack`` -- which is a success.
    """

    job_id: str
    attempts: int
    digest: str
    seq: int
    schema: str = JOB_QUEUE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin("dead", self.job_id, self.attempts, self.seq)
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

    def __init__(self, *, refusal_gate: Optional[Any] = None) -> None:
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
        #: The optional **refusal gate** (see
        #: ``refusal_hold_wiring.RefusalHoldQueueGate``).  When one is
        #: installed, a job whose re-dispatch is covered by a recorded
        #: refusal is NOT put back to ``ready`` -- ``retry()`` refuses
        #: the write and the job stays where it is.
        #:
        #: The gate is **duck-typed**: this module does not import the
        #: wiring (the wiring imports the hold, and the hold must not
        #: drag the queue ledger in).  It must offer
        #: ``require_queue_allowed(job_id, action, now=...)``.
        #:
        #: WHY IT LIVES HERE (measured 2026-11-23):  before this, the
        #: queue side had the gate only as an opt-in context manager
        #: (``install_queue_refusal_gate``), which the HOST had to
        #: remember to use at every call site.  A plain ``retry()``
        #: returned the job to ``ready`` with the refusal on the books.
        #: The lease side (``leased_task_claim``) never had that hole,
        #: because its gate is inside the object.  This is the same
        #: seam, closed the same way.
        self._refusal_gate = refusal_gate

    @property
    def refusal_gate(self) -> Optional[Any]:
        """The installed refusal gate, if any."""
        return self._refusal_gate

    def set_refusal_gate(self, gate: Optional[Any]) -> None:
        """Install (or remove) the refusal gate.

        The gate is asked about the job's **action identity**, which the
        job already carries: the ``task`` string of the enqueue is the
        work item's action, so no schema change is needed.
        """
        self._refusal_gate = gate

    def _require_refusal_allows(self, job_id: str, action: str,
                                now: Optional[float]) -> None:
        """Ask the refusal gate, if one is installed.

        Called **inside** ``retry()``'s lock, immediately before the
        entry is flipped back to ``ready``.  A refusal raises, so the
        job keeps its state, its attempt count and its backoff -- and
        the gate's answer and the write are serialized, because both
        happen under the same lock.
        """
        gate = self._refusal_gate
        if gate is None:
            return
        require = getattr(gate, "require_queue_allowed", None)
        if not callable(require):
            raise TypeError(
                "the refusal gate must offer require_queue_allowed(job_id, "
                f"action, now=...), got {type(gate).__name__}"
            )
        require(job_id, action, now=now)

    def _require_refusal_allows_dequeue(
        self, job_id: str, action: str, now: Optional[float]
    ) -> None:
        """Ask the refusal gate before a job is HANDED OUT.

        Called **inside** ``dequeue()``'s lock, immediately before the
        entry is flipped to ``reserved`` and offered to a worker.

        **Why ``dequeue`` asks at all.**  ``retry()`` puts a job back
        into ``ready``; ``dequeue()`` takes it **out** and offers it to
        somebody.  Both are the re-dispatch: the first makes the action
        available again, the second is the moment it is actually
        issued.  A refusal says "this action may not be issued", and a
        gate that guards only ``retry()`` can be walked around by
        dequeueing the job directly.

        The lease side already had this seam -- ``leased_task_claim``'s
        ``claim()`` asks the gate before it installs the lease, and it
        was the ASYMMETRY that exposed this one: the lease side
        guarded both ``fail()`` and ``claim()``, and the queue side
        guarded only ``retry()``.  Measured 2026-11-23, before the fix:

            check job-1/send_email: blocked_by_refusal
            DEQUEUE RESULT: ('job-1', 'send_email', 'w-1')
            job state: reserved

        -- the refused action was handed to a worker while the refusal
        was on the books.

        **The check is raised, not boolean.**  ``dequeue()`` reports ONE
        job for ONE call, and the caller asked about that job and
        nothing else -- exactly like ``retry()``.  (The batch-safe form
        is ``retry_allowed()``; there is no batch sweep over dequeues,
        so inventing a boolean form here would create a second question
        with a different answer.)

        **Which jobs are asked about.**  The gate is asked about the
        candidates **in the queue's own order**, and the first candidate
        it ALLOWS is the one handed out.  A refused candidate is
        **skipped**, and the next candidate is asked about.

        The first version of this asked only about the HEAD of the
        eligible list and let a refused head block the whole dequeue.
        That was justified as "the queue's contract is FIFO-by-priority,
        so skipping the refused job would silently reorder the queue" --
        and it was **wrong**, because the refusal is scoped to ONE
        (job, action) pair, not to the queue.  Measured 2026-11-23, on
        the version that asked only about the head:

            --- refused HEAD, two healthy jobs behind it ---
            dequeue raised: RefusalRefusedError
            states: [('j1', 'ready'), ('j2', 'ready'), ('j3', 'ready')]

            --- can the refused job ever be retired? ---
            ack   raised: JobStateError job j1 is ready, only reserved jobs may be acked
            dead  raised: JobStateError job j1 is ready, only reserved jobs may be killed
            retry raised: JobStateError job j1 is ready, only reserved jobs may be retried

            --- does j2 ever become reachable? ---
            dequeue raised: RefusalRefusedError   (x3, forever)

        So one refusal against ONE job wedged the **entire queue**: the
        refused job could never be retired (every terminal operation
        needs it ``reserved``, and it could never be reserved), and it
        blocked every job behind it, **permanently**.  That is the
        refusal's own denial of service -- the very thing §13.1's table
        says a refusal must not be able to do.

        The reordering worry is real but it is the wrong worry: the
        refusal already means "this job is not the next one to be
        handed out", so skipping it does not reorder anything the
        refusal did not already reorder.  A **refused** job is not
        eligible in the first place.

        **A broken gate is NOT a refusal.**  The skip is only sound for
        a per-job refusal; a gate that cannot answer at all is a
        property of the GATE, and skipping it would turn a broken gate
        into a silently degraded queue -- fail-OPEN.  See
        :func:`_is_refusal`.

        **Why this is safe here and not in the mirror's case.**  The
        queue's own dispatcher reads the ledger and chooses which job to
        offer; skipping a refused one is the dispatcher's business.  The
        MIRROR's reservation is a by-task operation with a **fixed
        target**: the mirror must reserve *that* task's job, and there
        is no "the next one" for it to fall back to.  Handing out a
        DIFFERENT task's job there would break the two ledgers'
        correspondence -- which is what ``QueueMirrorError`` exists to
        prevent.  So the mirror asks about its own task and takes the
        refusal, and the lease transaction rolls back.
        """
        gate = self._refusal_gate
        if gate is None:
            return
        require = getattr(gate, "require_queue_allowed", None)
        if not callable(require):
            raise TypeError(
                "the refusal gate must offer require_queue_allowed(job_id, "
                f"action, now=...), got {type(gate).__name__}"
            )
        require(job_id, action, now=now)

    def _refusal_allows(self, job_id: str, action: str,
                        now: Optional[float]) -> Tuple[bool, Optional[BaseException]]:
        """The **boolean** form of the refusal question, and the reason.

        :meth:`_require_refusal_allows` raises, and a raise is right
        for a caller that reports ONE job for ONE call.  It is wrong
        for a caller that sweeps a **batch**: one refused job would
        abandon the whole sweep, which is a denial of service the
        refusal never asked for.

        So the batch form turns a refusal into ``False`` -- and a gate
        that cannot answer at all is also ``False``, because the hold
        fails closed.

        **The reason comes back too.**  The boolean alone was not
        enough: the batch form caught the gate's exception and threw
        it away, so a sweep's refusal was not just un-named in the
        queue's trail -- the *reason* was gone from the caller's hands
        as well.  The second element of the tuple is the exception
        that caused the refusal, or ``None`` when the job is allowed.

        **The RAISING form is the one that is asked.**  This used to
        prefer the gate's *boolean* form (``queue_allowed``) and fall
        back to the raising one.  That was wrong twice over.

        1. **The two forms can disagree.**  A host gate that offers
           both is expected to answer both the same way -- they are
           the same question -- but nothing enforced it, so the batch
           form could be MORE PERMISSIVE than the raising form.  And
           the repo's own gate offers only ``require_queue_allowed``
           (the queue side has no boolean method at all), so the
           boolean branch was **dead code against the real contract**:
           the one path in it was a path no host takes.

           Measured 2026-11-24, on the tree as §17 left it:

               --- the RAISING form ---
               retry raised: RuntimeError refused
               state j1: reserved

               --- the BATCH form, the SAME gate, the SAME job ---
               retry_allowed -> RetryRecord(..., state='ready')
               state j1: ready

           The gate refused the re-dispatch and the batch form
           re-dispatched it anyway: the refused action went back to
           ``ready``, so it was offered again.

        2. **The boolean form cannot say WHY.**  It answers ``False``
           for a recorded refusal *and* for a gate that cannot answer
           at all -- the hold fails closed, so both are ``False``.  So
           the batch form could not tell a refusal from a broken gate,
           and it booked a ``job.rejected`` row for a gate that
           "refused nothing in particular" -- the exact row §17's rule
           forbids.  And when the boolean form answered ``False``
           without raising, the row's ``reason`` was the class name of
           the *missing* exception: ``"NoneType"``.

        Asking the **raising** form fixes all three: it names the
        reason, it tells a refusal from a broken gate (``_is_refusal``
        draws that line), and it is the form the raising form of
        ``retry()`` already asks -- so the two forms of ``retry()``
        are now the SAME question asked the same way.

        A caller that ignores the second element gets the old
        behaviour exactly; nothing about the boolean changed.
        """
        gate = self._refusal_gate
        if gate is None:
            return True, None
        require = getattr(gate, "require_queue_allowed", None)
        if not callable(require):
            allows = getattr(gate, "queue_allowed", None)
            if not callable(allows):
                raise TypeError(
                    "the refusal gate must offer require_queue_allowed("
                    "job_id, action, now=...) or queue_allowed(job_id, "
                    f"action, now=...), got {type(gate).__name__}"
                )
            # A gate with ONLY the boolean form is a host that implements
            # the contract partially.  It is still asked, because asking
            # it is better than not asking -- but its answer cannot
            # name a reason, so the row would carry a reason that names
            # nothing.  ``UnnamedRefusalError`` is that reason, and it
            # is a REAL class: the row never says "NoneType".
            try:
                allowed = bool(allows(job_id, action, now=now))
            except Exception as exc:
                return False, exc
            if allowed:
                return True, None
            return False, UnnamedRefusalError(
                "the refusal gate refused without saying why: it offers "
                "only the boolean form, which does not carry a reason"
            )
        try:
            require(job_id, action, now=now)
        except Exception as exc:
            return False, exc
        return True, None

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

    def _reject_refusal(
        self,
        seq: int,
        job_id: str,
        action: str,
        exc: BaseException,
    ) -> Dict[str, Any]:
        """Book ONE refused candidate in the queue's own audit trail.

        ``job.rejected`` is an existing kind -- no new kind is added.

        The row names **who** was refused (the job id), **what** was
        refused (the action), and **why**: ``reason`` is the error's
        class name, and ``refusal_reason`` is the hold's reason *slug*
        (``blocked_by_refusal``, ``blocked_store_unreadable``,
        ``blocked_key_invalid``, ...).  The two are not the same thing:
        the class name is the same for every refusal, so a trail built
        from the class name alone cannot tell a recorded refusal from
        a gate that could not read its own store.

        The slug is optional: a host that re-implements the gate's
        contract may raise an error that carries only the class name.
        Then the slug is ``None`` -- the row still says *that* the
        candidate was refused.
        """
        slug = getattr(exc, "reason", None)
        if not isinstance(slug, str):
            slug = None
        row = job_queue_audit_event(
            KIND_REJECTED,
            {
                "reason": type(exc).__name__,
                "refusal_reason": slug,
                "job_id": job_id,
                "action": action,
            },
            seq,
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
                # The digest is computed INSIDE the guarded block, so an
                # identity the canonicalizer refuses is booked as a
                # rejection like every other refused call.  Left
                # outside, the refusal raised past the ``except`` and
                # the trail showed nothing at all -- see
                # :func:`_canonical`.
                digest = _pin(
                    "enqueue",
                    job_id,
                    queue,
                    task,
                    payload_digest,
                    priority,
                    max_retries,
                    delay_seqs,
                    seq,
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
                digest=digest,
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
        self, worker_id: str, queue: str, seq: int,
        now: Optional[float] = None,
    ) -> Optional[DequeuedJob]:
        """Reserve the next eligible job in ``queue`` for a worker.

        Order: priority desc, then FIFO by enqueue seq. Eligibility
        requires ``not_before_seq <= seq`` (logical-seq backoff). The
        job becomes ``reserved`` (invisible) and ``attempts`` increments
        as data. An empty queue or no eligible job returns ``None`` as
        data -- emptiness is not a failure. Unknown queues fail closed.

        **A recorded refusal blocks the hand-out.**  When a refusal gate
        is installed and a refusal covers the job's action, the job is
        NOT handed to a worker: it stays ``ready``.  ``dequeue()`` is the
        moment the action is actually **issued**, so it is a re-dispatch
        as much as ``retry()`` is -- see
        :meth:`_require_refusal_allows_dequeue`.

        **A refused candidate is SKIPPED, not fatal.**  The gate is asked
        about the candidates in the queue's own order, and the first
        candidate the gate **allows** is the one handed out.  A refusal
        is scoped to one (job, action) pair, so it must not be able to
        deny the queue to every other job -- see
        :meth:`_require_refusal_allows_dequeue` for the measurement that
        forced this.  When EVERY candidate is refused, the call raises
        the gate's own refusal error and nothing is handed out.

        **Every refused candidate is audited, in this trail.**  Each one
        books its own ``job.rejected`` row naming the job, the action
        and the hold's reason slug -- including a candidate that was
        *skipped* because a healthy job behind it was handed out.  The
        registry books one ``checked`` event per candidate (§8); this
        trail books one row per **refused** candidate, so the two
        trails agree on how many candidates were refused.  A broken gate
        is not a refusal and books no row.
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
            # The gate is asked about the candidates in the queue's own
            # order, and the FIRST candidate the gate ALLOWS is the one
            # handed out.  A refused candidate is SKIPPED, not fatal: a
            # refusal is scoped to one (job, action) pair, so it must
            # not be able to deny the queue to every other job.
            #
            # See :meth:`_require_refusal_allows_dequeue` for the
            # measurement that forced this, and for why the skip is safe
            # here in a way it is NOT safe in the mirror's case.
            first_refusal: Optional[BaseException] = None
            job_id = None
            entry = None
            for candidate in eligible:
                candidate_entry = self._entries[candidate]
                candidate_action = str(candidate_entry["task"])
                try:
                    self._require_refusal_allows_dequeue(
                        candidate, candidate_action, now
                    )
                except Exception as exc:
                    if not _is_refusal(exc):
                        # Not a refusal: the gate itself is broken (or
                        # unusable).  That is NOT a per-job condition,
                        # so it is NOT skipped -- it fails the whole
                        # call, closed.  And it is NOT recorded as a
                        # refusal either: a broken gate refuses
                        # nothing in particular, so a ``job.rejected``
                        # row would put a refusal in the trail that
                        # never happened.
                        raise
                    if first_refusal is None:
                        first_refusal = exc
                    # AUDIT the skip, per candidate.  The registry
                    # books a ``checked`` event for every candidate
                    # (§8), but the queue's OWN trail had nothing at
                    # all for a candidate that was passed over -- so a
                    # host reading this trail could not tell "the
                    # queue skipped a refused job" from "the queue
                    # never looked at it".  Every refused candidate is
                    # named here, so the trail and the registry's
                    # trail agree on HOW MANY candidates were refused.
                    self._reject_refusal(
                        seq, candidate, candidate_action, exc
                    )
                    continue
                job_id = candidate
                entry = candidate_entry
                break
            if job_id is None or entry is None:
                # EVERY candidate is refused.  The caller is told, and
                # nothing was handed out: no job is reserved, no worker
                # holds one, and no attempt was booked.
                #
                # The gate's OWN refusal error is raised, so the host
                # catches it with the vocabulary it already knows.
                #
                # The refusals are ALREADY booked -- one row per
                # refused candidate, above -- so this path books
                # nothing more: a second row would double-count the
                # first candidate's refusal.
                assert first_refusal is not None
                raise first_refusal
            # The digest is computed BEFORE the entry is flipped.  A
            # worker id the canonicalizer refuses must not leave the
            # job RESERVED with no record and no ``job.dequeued`` row:
            # measured before this fix, ``dequeue()`` raised, the
            # entry stayed ``reserved``, and ``stats()`` reported
            # ``reserved=1, dequeued=0`` -- a job nobody holds and
            # nobody can account for.
            #
            # The refusal is BOOKED, so the trail says the queue
            # refused this hand-out rather than showing nothing.
            try:
                digest = _pin(
                    "dequeue",
                    job_id,
                    queue,
                    entry["task"],
                    entry["payload_digest"],
                    worker_id,
                    entry["attempts"] + 1,
                    entry["priority"],
                    seq,
                )
            except JobQueueError as exc:
                self._reject(seq, type(exc).__name__, job_id)
                raise
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
                digest=digest,
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
                # Computed inside the guarded block, so a refused
                # digest is booked as a rejection and the job is left
                # exactly where it was -- see :func:`_canonical`.
                digest = _pin("ack", job_id, entry["attempts"], seq)
            except JobQueueError as exc:
                self._reject(seq, type(exc).__name__, job_id)
                raise
            record = AckRecord(
                job_id=job_id,
                attempts=entry["attempts"],
                digest=digest,
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

    def dead(self, job_id: str, seq: int) -> DeadRecord:
        """Terminal **failure** of a reserved job.

        The job goes to ``dead``: it is never handed out again, and
        no ``dequeue`` will ever select it.  This is the ledger's own
        terminal-failure operation, and it is distinct from the two
        other terminal-ish outcomes:

        * ``ack()`` -- terminal **success** (``done``);
        * ``retry()`` -- a failure that will be re-dispatched
          (``ready``), unless the retry budget is already spent, in
          which case ``retry()`` marks the job ``dead`` itself.

        Only ``reserved`` jobs may be killed; anything else raises
        ``JobStateError`` fail-closed.

        **A recorded refusal does not block this.**  The refusal
        semantics are about the **re-dispatch**: a refusal says the
        work item may not be *offered again*.  A job that is being
        killed is not being offered again -- it is being withdrawn.
        So ``dead()`` does not consult the gate, exactly as ``ack()``
        does not: a refusal must not be able to keep a finished work
        item in the queue forever, which would be the refusal's own
        denial of service.
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
                        "only reserved jobs may be killed"
                    )
                # Computed inside the guarded block -- see
                # :func:`_canonical`.
                digest = _pin("dead", job_id, entry["attempts"], seq)
            except JobQueueError as exc:
                self._reject(seq, type(exc).__name__, job_id)
                raise
            record = DeadRecord(
                job_id=job_id,
                attempts=entry["attempts"],
                digest=digest,
                seq=seq,
            )
            entry["state"] = _STATE_DEAD
            entry["worker_id"] = ""
            self._dead += 1
            self._audit.append(
                job_queue_audit_event(
                    KIND_DEAD,
                    {"job_id": job_id, "attempts": entry["attempts"]},
                    seq,
                )
            )
            return record

    def retry(
        self, job_id: str, seq: int, delay_seqs: int = 0,
        now: Optional[float] = None,
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

        **A recorded refusal blocks the re-dispatch.**  When a refusal
        gate is installed (see :attr:`refusal_gate`) and a refusal
        covers this job's action, the write is refused: the job does
        not go back to ``ready``, its attempt count does not advance,
        and no backoff is booked.  The check runs inside the queue's
        own lock, immediately before the entry is flipped, so a refusal
        and the re-dispatch cannot interleave.
        """
        record = self._retry(job_id, seq, delay_seqs, now=now, batch=False)
        assert record is not None  # the raising form never returns None
        return record

    def retry_allowed(self, job_id: str, seq: int, delay_seqs: int = 0,
                      now: Optional[float] = None) -> Optional[RetryRecord]:
        """The **batch-safe** form of :meth:`retry`.

        :meth:`retry` raises when the refusal gate refuses the
        re-dispatch.  That is right for a caller that reports ONE job
        for ONE call, and wrong for a caller that sweeps a **batch**:
        one refused job would abandon the whole sweep, which is a
        denial of service the refusal never asked for.

        So this form returns ``None`` for "not re-dispatched" -- a
        refused job, a job that is not reserved, an unknown job, or a
        job whose retry budget is spent.  The job is left exactly where
        it was.

        ``None`` here means "not re-dispatched", exactly as
        ``dequeue``'s ``None`` means "no job" -- it is data, not a
        failure.

        The gate is consulted **once**, by the same writer that
        :meth:`retry` uses: a batch of three jobs is three checks, not
        six.
        """
        return self._retry(job_id, seq, delay_seqs, now=now, batch=True)

    def _retry(self, job_id: str, seq: int, delay_seqs: int,
               *, now: Optional[float], batch: bool) -> Optional[RetryRecord]:
        """The one writer behind :meth:`retry` and :meth:`retry_allowed`.

        ``batch`` chooses the SHAPE of the refusal question, not
        whether it is asked:

        * ``batch=False`` -- the RAISING form.  A refusal raises, so
          the caller learns the reason.  One job, one call.
        * ``batch=True`` -- the BOOLEAN form.  A refusal is "not
          allowed", so one refused job cannot abandon a sweep.

        Both forms ask the gate **once**, under the same lock, at the
        same point: immediately before the entry is flipped back to
        ``ready``.  That is what makes the two forms agree, and it is
        what keeps the audit trail's event count equal to the number
        of jobs the caller asked about.

        **A refusal is booked in the queue's OWN trail**, on both
        forms, as a ``job.rejected`` row naming the job, the action
        and the hold's reason slug.  Without it the trail showed
        "dequeued, then nothing", which is indistinguishable from a
        worker that died mid-flight.  The batch form asks the boolean
        gate question, so it needs the reason handed back to it --
        hence ``_refusal_allows()``'s tuple.  A **broken** gate books
        no row: it refuses nothing in particular.
        """
        with self._lock:
            self._claim(seq)
            # Set when the exception that reached the generic handler
            # below came from the REFUSAL GATE, rather than from the
            # queue's own validation.  The gate's exception is not a
            # queue-level rejection: a refusal books its own row (in
            # the refusal branch, where the reason and the action are
            # both in hand), and a broken gate books NO row at all --
            # it refuses nothing in particular.  So the generic
            # handler must not book a second row for it.
            _gate_raised = False
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
                # The refusal gate is asked BEFORE the budget check, so a
                # refusal is reported as a refusal rather than as an
                # exceeded budget -- and before the entry is flipped, so
                # a refusal leaves the job exactly where it was.
                retry_action = str(entry["task"])
                # The READY digest is computed inside the guarded
                # block, so a refused digest is booked as a rejection
                # and the job is left exactly where it was.  See
                # :func:`_canonical`.
                ready_digest = _pin(
                    "retry",
                    job_id,
                    entry["attempts"],
                    delay_seqs,
                    entry["max_retries"],
                    _STATE_READY,
                    seq,
                )
                if batch:
                    allowed, exc = self._refusal_allows(
                        job_id, retry_action, now
                    )
                    if not allowed:
                        # AUDIT the refusal, on the queue's own trail.
                        # The batch form returns a bare ``None`` -- "not
                        # re-dispatched" -- so without this row the
                        # refusal was invisible here: the trail showed
                        # "dequeued, then nothing", which is
                        # indistinguishable from a worker that died.
                        #
                        # A BROKEN gate books no row, exactly as the
                        # raising form does below: a broken gate
                        # refuses nothing in particular, so a
                        # ``job.rejected`` row would put a refusal in
                        # the trail that never happened.  ``_is_refusal``
                        # draws that line, and both forms use it.
                        if exc is not None and _is_refusal(exc):
                            self._reject_refusal(
                                seq, job_id, retry_action, exc
                            )
                        return None
                else:
                    # The raising form: the gate raises, so the caller
                    # is told the REASON, and the job is left where it
                    # was.  One call, one audit event.
                    try:
                        self._require_refusal_allows(
                            job_id, retry_action, now
                        )
                    except Exception as exc:
                        # The gate's exception is NOT a queue-level
                        # rejection, so the generic ``except
                        # JobQueueError`` handler below must not book
                        # a row for it.
                        #
                        # A REFUSAL is booked here, where the reason
                        # and the action are both in hand.  A BROKEN
                        # gate is not booked at all: it refuses nothing
                        # in particular, so a ``job.rejected`` row
                        # would put a refusal in the trail that never
                        # happened.  ``_is_refusal`` draws that line.
                        #
                        # The flag is what keeps the two forms
                        # agreeing.  Without it the raising form
                        # booked a SECOND row for the same refusal
                        # (through the generic handler) -- with a
                        # different shape, so a reader of the trail
                        # got two different stories about one event --
                        # and booked a row for a BROKEN gate that
                        # raised the queue's own base error, which
                        # the batch form did not.
                        _gate_raised = True
                        if _is_refusal(exc):
                            self._reject_refusal(
                                seq, job_id, retry_action, exc
                            )
                        raise
                if entry["attempts"] >= entry["max_retries"]:
                    # The digest is computed BEFORE the entry is
                    # flipped, so a refused digest leaves the job
                    # exactly where it was -- reserved, not dead.
                    # See :func:`_canonical`.
                    dead_digest = _pin(
                        "retry",
                        job_id,
                        entry["attempts"],
                        delay_seqs,
                        entry["max_retries"],
                        _STATE_DEAD,
                        seq,
                    )
                    entry["state"] = _STATE_DEAD
                    entry["worker_id"] = ""
                    dead_record = RetryRecord(
                        job_id=job_id,
                        attempts=entry["attempts"],
                        delay_seqs=delay_seqs,
                        max_retries=entry["max_retries"],
                        state=_STATE_DEAD,
                        digest=dead_digest,
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
                    if batch:
                        # The batch form books the same row the raising
                        # form books below, so the two forms leave the
                        # same trail for the same event.  The raising
                        # form's row arrives through the generic
                        # ``except JobQueueError`` handler; the batch
                        # form returns ``None`` instead of raising, so
                        # it must book it here or the trail would say
                        # the two forms saw different things.
                        self._reject(
                            seq, MaxRetriesExceededError.__name__, job_id
                        )
                        return None
                    raise MaxRetriesExceededError(
                        f"max_retries={entry['max_retries']} exceeded "
                        f"for {job_id}"
                    )
            except JobQueueError as exc:
                if not _gate_raised:
                    self._reject(seq, type(exc).__name__, job_id)
                if batch:
                    return None
                raise
            record = RetryRecord(
                job_id=job_id,
                attempts=entry["attempts"],
                delay_seqs=delay_seqs,
                max_retries=entry["max_retries"],
                state=_STATE_READY,
                digest=ready_digest,
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

    # Terminal FAILURE, distinct from ack() and from the retry budget.
    jq3 = JobQueue()
    jq3.enqueue("j-kill", "critical", "charge", lo, 1)
    assert jq3.dequeue("w-9", "critical", 2) is not None
    killed = jq3.dead("j-kill", 3)
    assert killed.verify() and jq3.job("j-kill").state == "dead"
    assert jq3.dequeue("w-9", "critical", 4) is None

    # The batch-safe re-dispatch: an unknown job is "not re-dispatched",
    # not an exception.
    jq4 = JobQueue()
    jq4.enqueue("j-batch", "default", "charge", lo, 1)
    assert jq4.dequeue("w-9", "default", 2) is not None
    assert jq4.retry_allowed("ghost", 3) is None
    assert jq4.retry_allowed("j-batch", 4) is not None
    assert jq4.job("j-batch").state == "ready"

    stats = jq.stats()
    assert (stats.enqueued, stats.dequeued, stats.queues) == (2, 3, 1)
    print(
        "job-queue OK: enqueue, priority, dequeue, ack, dead, retry, "
        "delay, dead-lettering"
    )


if __name__ == "__main__":
    main()
