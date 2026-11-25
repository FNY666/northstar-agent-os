"""Tests for job_queue: Celery/Sidekiq-shaped job lifecycle bookkeeping."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import job_queue
from job_queue import (
    AckRecord,
    AuditKindError,
    BadDelayError,
    BadDigestError,
    BadJobError,
    BadPriorityError,
    BadQueueError,
    BadRetryError,
    BadTaskError,
    BadWorkerError,
    DequeuedJob,
    DeadRecord,
    DuplicateJobError,
    EnqueueRecord,
    JobQueue,
    JobQueueError,
    JobStateError,
    MaxRetriesExceededError,
    RetryRecord,
    SeqOrderError,
    UnknownJobError,
    UnknownQueueError,
    job_queue_audit_event,
)


def _digest(v: str) -> str:
    return job_queue._pin("value", v)


def _enqueue(jq, job_id="j-1", queue="default", task="send_email",
             seq=1, **kw):
    return jq.enqueue(job_id, queue, task, _digest(job_id), seq, **kw)


def _dequeue_around_the_gate(jq):
    """Reserve a job WITHOUT the gate in the way; return the ask count.

    ``dequeue()`` consults the refusal gate -- it is the moment the
    action is actually issued -- so a test that counts the gate's asks
    around the RETRY path has to take the dequeue out of that count.
    The gate is removed for the dequeue and put back afterwards, and the
    ask count at that moment is the baseline the retry's count is
    measured from.

    Removing the gate is not a way of making a refusal disappear: the
    refusal the tests are about is recorded in the hold, and the gate
    is asked again by the path under test.
    """
    current = jq.refusal_gate
    jq.set_refusal_gate(None)
    try:
        jq.dequeue("w-1", "default", 2)
    finally:
        jq.set_refusal_gate(current)
    return getattr(current, "asked", 0)


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert job_queue.JOB_QUEUE_VERSION == "job-queue.v1"
    assert job_queue.JOB_QUEUE_SCHEMA == "northstar.job-queue.v1"
    assert job_queue.AUDIT_SCHEMA == "audit.ndjson/1"
    jq = JobQueue()
    assert jq.stats().schema == job_queue.JOB_QUEUE_SCHEMA


# ---------------------------------------------------------------------------
# 2. stdlib-only
# ---------------------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(Path(job_queue.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses",
               "typing", "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, \
                node.module


# ---------------------------------------------------------------------------
# 3. enqueue roundtrip
# ---------------------------------------------------------------------------


def test_enqueue_roundtrip():
    jq = JobQueue()
    rec = _enqueue(jq, priority=5, max_retries=2, delay_seqs=4)
    assert isinstance(rec, EnqueueRecord)
    assert rec.priority == 5 and rec.max_retries == 2
    assert rec.delay_seqs == 4 and rec.verify()
    view = jq.job("j-1")
    assert view is not None and view.state == "ready"
    assert view.attempts == 0 and view.not_before_seq == 5
    assert jq.ready("default") == ("j-1",)


# ---------------------------------------------------------------------------
# 4. duplicate job id refused + seq consumed + rejected audit
# ---------------------------------------------------------------------------


def test_enqueue_duplicate_refused():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    before = len(jq.audit_log())
    with pytest.raises(DuplicateJobError):
        _enqueue(jq, seq=2)
    assert len(jq.audit_log()) == before + 1
    assert jq.audit_log()[-1]["kind"] == "job.rejected"
    # failed seq is consumed: reuse raises SeqOrderError
    with pytest.raises(SeqOrderError):
        _enqueue(jq, "j-2", seq=2)


# ---------------------------------------------------------------------------
# 5. bad inputs fail closed
# ---------------------------------------------------------------------------


def test_enqueue_bad_inputs():
    jq = JobQueue()
    good = dict(queue="default", task="t", digest=_digest("x"))
    cases = [
        dict(job_id="", queue="default", task="t", digest=_digest("x")),
        dict(job_id=True, queue="default", task="t", digest=_digest("x")),
        dict(job_id="j", queue="", task="t", digest=_digest("x")),
        dict(job_id="j", queue="default", task="", digest=_digest("x")),
        dict(job_id="j", queue="default", task="t",
             digest="not-a-digest"),
        dict(job_id="j", queue="default", task="t",
             digest="SHA256:" + "ab" * 32),
        dict(job_id="j", queue="default", task="t", digest=_digest("x"),
             priority=True),
        dict(job_id="j", queue="default", task="t", digest=_digest("x"),
             priority=101),
        dict(job_id="j", queue="default", task="t", digest=_digest("x"),
             priority=-101),
        dict(job_id="j", queue="default", task="t", digest=_digest("x"),
             max_retries=0),
        dict(job_id="j", queue="default", task="t", digest=_digest("x"),
             max_retries=65),
        dict(job_id="j", queue="default", task="t", digest=_digest("x"),
             delay_seqs=-1),
        dict(job_id="j", queue="default", task="t", digest=_digest("x"),
             delay_seqs=True),
    ]
    seq = 1
    for c in cases:
        with pytest.raises(JobQueueError):
            jq.enqueue(
                c.get("job_id", "j-%d" % seq),
                c.get("queue", "default"),
                c.get("task", "t"),
                c.get("digest", _digest("x")),
                seq,
                priority=c.get("priority", 0),
                max_retries=c.get("max_retries", 3),
                delay_seqs=c.get("delay_seqs", 0),
            )
        seq += 1
    assert jq.stats().enqueued == 0


# ---------------------------------------------------------------------------
# 6. dequeue priority + FIFO ordering
# ---------------------------------------------------------------------------


def test_dequeue_priority_fifo():
    jq = JobQueue()
    _enqueue(jq, "a", seq=1, priority=0)
    _enqueue(jq, "b", seq=2, priority=10)
    _enqueue(jq, "c", seq=3, priority=10)
    assert jq.ready("default") == ("b", "c", "a")
    first = jq.dequeue("w-1", "default", 4)
    assert isinstance(first, DequeuedJob)
    assert first.job_id == "b" and first.attempts == 1
    assert first.worker_id == "w-1" and first.verify()
    second = jq.dequeue("w-2", "default", 5)
    assert second.job_id == "c" and second.attempts == 1
    assert jq.reserved() == ("b", "c")
    assert jq.job("b").state == "reserved"


# ---------------------------------------------------------------------------
# 7. dequeue empty queue is data
# ---------------------------------------------------------------------------


def test_dequeue_empty_is_none():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    got = jq.dequeue("w-1", "default", 2)
    assert got is not None
    assert jq.dequeue("w-2", "default", 3) is None
    # unknown queue fails closed
    with pytest.raises(UnknownQueueError):
        jq.dequeue("w-1", "nope", 4)
    with pytest.raises(BadWorkerError):
        jq.dequeue("", "default", 5)


# ---------------------------------------------------------------------------
# 8. ack lifecycle
# ---------------------------------------------------------------------------


def test_ack_lifecycle():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    got = jq.dequeue("w-1", "default", 2)
    assert got is not None
    rec = jq.ack("j-1", 3)
    assert isinstance(rec, AckRecord)
    assert rec.attempts == 1 and rec.verify()
    assert jq.job("j-1").state == "done"
    assert jq.reserved() == ()
    # ack of a non-reserved job fails closed
    with pytest.raises(JobStateError):
        jq.ack("j-1", 4)
    with pytest.raises(UnknownJobError):
        jq.ack("ghost", 5)


# ---------------------------------------------------------------------------
# 9. retry with delay backoff
# ---------------------------------------------------------------------------


def test_retry_delay_backoff():
    jq = JobQueue()
    _enqueue(jq, seq=1, max_retries=3)
    got = jq.dequeue("w-1", "default", 2)
    assert got is not None
    rec = jq.retry("j-1", 3, delay_seqs=10)
    assert isinstance(rec, RetryRecord)
    assert rec.state == "ready" and rec.attempts == 1
    assert rec.verify()
    assert jq.job("j-1").not_before_seq == 13
    # backoff has not elapsed: nothing eligible
    assert jq.dequeue("w-2", "default", 4) is None
    # attempts are not double-counted by retry
    got2 = jq.dequeue("w-2", "default", 13)
    assert got2 is not None and got2.attempts == 2


# ---------------------------------------------------------------------------
# 10. retry beyond max_retries -> dead
# ---------------------------------------------------------------------------


def test_retry_budget_exhaustion():
    jq = JobQueue()
    _enqueue(jq, seq=1, max_retries=2)
    jq.dequeue("w-1", "default", 2)  # attempt 1
    jq.retry("j-1", 3)                # 1 < 2: requeue
    jq.dequeue("w-1", "default", 4)   # attempt 2
    with pytest.raises(MaxRetriesExceededError):
        jq.retry("j-1", 5)            # 2 >= 2: dead
    assert jq.job("j-1").state == "dead"
    assert jq.audit_log()[-2]["kind"] == "job.dead"
    # dead is terminal: retry/ack/dequeue all fail closed
    with pytest.raises(JobStateError):
        jq.retry("j-1", 6)
    with pytest.raises(JobStateError):
        jq.ack("j-1", 7)
    assert jq.stats().dead == 1


# ---------------------------------------------------------------------------
# 11. retry/ack only from reserved
# ---------------------------------------------------------------------------


def test_retry_ack_state_guards():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    with pytest.raises(JobStateError):
        jq.retry("j-1", 2)
    with pytest.raises(UnknownJobError):
        jq.retry("ghost", 3)
    # bad delay fails closed (job must be reserved first)
    assert jq.dequeue("w-1", "default", 4) is not None
    with pytest.raises(BadDelayError):
        jq.retry("j-1", 5, delay_seqs=-1)
    assert jq.job("j-1").state == "reserved"


# ---------------------------------------------------------------------------
# 12. seq ordering discipline
# ---------------------------------------------------------------------------


def test_seq_ordering():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    with pytest.raises(SeqOrderError):
        _enqueue(jq, "j-2", seq=1)   # rewind
    with pytest.raises(SeqOrderError):
        jq.dequeue("w-1", "default", True)  # bool refused
    with pytest.raises(SeqOrderError):
        jq.dequeue("w-1", "default", -1)
    # read views validate shape but consume nothing
    assert jq.job("j-1") is not None
    _enqueue(jq, "j-2", seq=2)


# ---------------------------------------------------------------------------
# 13. audit shapes + banned keys + bad kind
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    jq.dequeue("w-1", "default", 2)
    jq.ack("j-1", 3)
    kinds = [row["kind"] for row in jq.audit_log()]
    assert kinds == ["job.enqueued", "job.dequeued", "job.acked"]
    for row in jq.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "job-queue.v1"
        assert "payload" not in row["detail"]
        assert "payload_bytes" not in row["detail"]
    with pytest.raises(AuditKindError):
        job_queue_audit_event("job.bogus", {}, 1)
    with pytest.raises(AuditKindError):
        job_queue_audit_event(
            "job.enqueued", {"payload": b"x"}, 1
        )


# ---------------------------------------------------------------------------
# 14. stats and isolation across queues
# ---------------------------------------------------------------------------


def test_stats_and_queue_isolation():
    jq = JobQueue()
    _enqueue(jq, "a", queue="default", seq=1)
    _enqueue(jq, "b", queue="critical", seq=2)
    jq.dequeue("w-1", "critical", 3)
    stats = jq.stats()
    assert (stats.ready, stats.reserved, stats.queues) == (1, 1, 2)
    assert stats.enqueued == 2 and stats.dequeued == 1
    # dequeue from default does not touch critical's reservation
    got = jq.dequeue("w-2", "default", 4)
    assert got is not None and got.job_id == "a"


# ---------------------------------------------------------------------------
# 16. dead(): terminal FAILURE, distinct from ack() and retry()
# ---------------------------------------------------------------------------
#
# WHY THIS OPERATION EXISTS (measured 2026-11-23)
# ----------------------------------------------
# ``ack()`` is terminal success and ``retry()`` is a re-dispatch.  A
# work item that failed for good had NO terminal operation: the only
# way to make a job terminal-failed was to exhaust its retry budget,
# which also books a ``MaxRetriesExceededError``.
#
# The lease mirror needed the missing operation: a task whose failure
# budget is exhausted is ``dead`` in the lease ledger, and its mirror
# job was being put back to ``ready`` -- so the queue advertised a
# finished work item as available.  See
# ``docs/design/refusal-hold-wiring.md`` §13.


def test_dead_moves_a_reserved_job_to_dead():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    assert jq.dequeue("w-1", "default", 2) is not None
    rec = jq.dead("j-1", 3)
    assert isinstance(rec, DeadRecord)
    assert rec.attempts == 1 and rec.verify()
    assert jq.job("j-1").state == "dead"
    assert jq.reserved() == ()


def test_a_dead_job_is_never_handed_out_again():
    """The point of a terminal state: it is not eligible."""
    jq = JobQueue()
    _enqueue(jq, seq=1)
    jq.dequeue("w-1", "default", 2)
    jq.dead("j-1", 3)
    assert jq.dequeue("w-2", "default", 4) is None
    assert jq.ready("default") == ()


def test_dead_is_terminal():
    """Every other mutation fails closed on a dead job."""
    jq = JobQueue()
    _enqueue(jq, seq=1)
    jq.dequeue("w-1", "default", 2)
    jq.dead("j-1", 3)
    with pytest.raises(JobStateError):
        jq.dead("j-1", 4)
    with pytest.raises(JobStateError):
        jq.ack("j-1", 5)
    with pytest.raises(JobStateError):
        jq.retry("j-1", 6)


def test_dead_of_a_job_that_is_not_reserved_fails_closed():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    with pytest.raises(JobStateError):
        jq.dead("j-1", 2)
    with pytest.raises(UnknownJobError):
        jq.dead("ghost", 3)


def test_dead_is_audited():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    jq.dequeue("w-1", "default", 2)
    jq.dead("j-1", 3)
    kinds = [row["kind"] for row in jq.audit_log()]
    assert kinds == ["job.enqueued", "job.dequeued", "job.dead"]
    row = jq.audit_log()[-1]
    assert row["detail"] == {"job_id": "j-1", "attempts": 1}


def test_dead_counts_in_the_stats():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    jq.dequeue("w-1", "default", 2)
    jq.dead("j-1", 3)
    assert jq.stats().dead == 1


def test_dead_does_not_consult_the_refusal_gate():
    """A refusal is about the RE-DISPATCH, not about the withdrawal.

    A refusal must not be able to keep a finished work item in the
    queue forever -- that would be the refusal's own denial of
    service.  So ``dead()`` does not ask the gate, exactly as
    ``ack()`` does not.
    """
    class RefusingGate:
        """Counts the asks, and refuses every one of them."""

        def __init__(self):
            self.asked = 0

        def require_queue_allowed(self, job_id, action, *, now=None):
            self.asked += 1
            raise AssertionError("the gate must not be asked by dead()")

    gate = RefusingGate()
    jq = JobQueue(refusal_gate=gate)
    _enqueue(jq, seq=1)
    # The dequeue DOES ask -- it is the moment the action is issued.
    # So the dequeue is made with the gate out of the way, and the
    # count the test reads is the one taken AFTER it.
    asked_after_dequeue = _dequeue_around_the_gate(jq)
    jq.dead("j-1", 3)
    assert gate.asked == asked_after_dequeue, (
        "dead() asked the refusal gate: a refusal must not be able to "
        "keep a finished work item in the queue forever"
    )
    assert jq.job("j-1").state == "dead"


# ---------------------------------------------------------------------------
# 17. retry_allowed(): the batch-safe form of retry()
# ---------------------------------------------------------------------------
#
# ``retry()`` RAISES when the refusal gate refuses the re-dispatch.
# That is right for a caller that reports ONE job for ONE call, and
# wrong for a caller that sweeps a BATCH: one refused job would
# abandon the whole sweep.


class _RefusingGate:
    """A gate that refuses every job, and counts how often it was asked."""

    def __init__(self):
        self.asked = 0

    def require_queue_allowed(self, job_id, action, *, now=None):
        self.asked += 1
        raise job_queue.JobQueueError("refused")


def test_retry_allowed_returns_none_for_a_refused_job():
    jq = JobQueue(refusal_gate=_RefusingGate())
    _enqueue(jq, seq=1)
    _dequeue_around_the_gate(jq)
    assert jq.retry_allowed("j-1", 3) is None
    assert jq.job("j-1").state == "reserved"


def test_retry_allowed_does_not_raise_on_a_refusal():
    """The whole point: one refused job must not abandon the sweep."""
    jq = JobQueue(refusal_gate=_RefusingGate())
    _enqueue(jq, seq=1)
    _dequeue_around_the_gate(jq)
    jq.retry_allowed("j-1", 3)   # must not raise


class _CountingGate:
    """A gate that ALLOWS every job, and counts how often it was asked."""

    def __init__(self):
        self.asked = 0

    def require_queue_allowed(self, job_id, action, *, now=None):
        self.asked += 1


def test_retry_allowed_asks_the_gate_exactly_once():
    """A batch of one job is ONE check, not two.

    The batch form and the raising form share one writer, so the
    gate is consulted once per job -- and the audit trail's event
    count equals the number of jobs the caller asked about.

    The DEQUEUE counts for nothing here: the job is handed out
    before the batch sweep asks about it, and that is a different
    question.  So the count is taken from a baseline after the
    dequeue -- see ``_dequeue_around_the_gate``.
    """
    gate = _RefusingGate()
    jq = JobQueue(refusal_gate=gate)
    _enqueue(jq, seq=1)
    asked_after_dequeue = _dequeue_around_the_gate(jq)
    jq.retry_allowed("j-1", 3)
    assert gate.asked - asked_after_dequeue == 1


def test_retry_allowed_asks_the_gate_once_when_the_job_is_allowed():
    """The same count on the ALLOWED path.

    The refused path returns before the write, so a second ask would
    not show up there -- the allowed path is where a double ask would
    be visible, and it is the path that runs for every ordinary
    re-dispatch.
    """
    gate = _CountingGate()
    jq = JobQueue(refusal_gate=gate)
    _enqueue(jq, seq=1)
    asked_after_dequeue = _dequeue_around_the_gate(jq)
    rec = jq.retry_allowed("j-1", 3)
    assert rec is not None
    assert gate.asked - asked_after_dequeue == 1, (
        "the gate was asked more than once for one job: a double ask "
        "books a double audit event and doubles the gate's own cost"
    )


def test_retry_allowed_requeues_an_allowed_job():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    jq.dequeue("w-1", "default", 2)
    rec = jq.retry_allowed("j-1", 3)
    assert rec is not None and rec.state == "ready"
    assert jq.job("j-1").state == "ready"


def test_retry_allowed_returns_none_for_an_unknown_job():
    jq = JobQueue()
    assert jq.retry_allowed("ghost", 3) is None


def test_retry_allowed_returns_none_for_a_job_that_is_not_reserved():
    jq = JobQueue()
    _enqueue(jq, seq=1)
    assert jq.retry_allowed("j-1", 2) is None


# ---------------------------------------------------------------------------
# 17b. the two forms must ask the SAME question
# ---------------------------------------------------------------------------
#
# ``retry()`` asks the gate's RAISING form
# (``require_queue_allowed``); ``retry_allowed()`` asked the BOOLEAN
# form (``queue_allowed``).  A host gate that offers both is expected to
# answer both the same way -- they are the same question -- but nothing
# in the contract said so and nothing checked it, so the two forms could
# disagree and the disagreement was invisible: the same gate, the same
# job, the same action, two answers.
#
# The batch form existed so that one refused job could not abandon a
# sweep.  It did not exist to answer a DIFFERENT question, and asking a
# different question made it MORE PERMISSIVE: it took the boolean
# answer and re-dispatched an action the raising form had refused.
#
# These guards live here, beside the other ``retry_allowed`` tests,
# because this file is where the batch form's API is specified.


class RefusalRefusedError(job_queue.JobQueueError):
    """The refusal shape the queue's taxonomy recognises.

    ``_is_refusal`` draws the line between a refusal and a broken gate
    on the error's own VOCABULARY: a ``reason`` attribute whose value is
    one of the hold's ``blocked_*`` reasons, or the class name
    ``RefusalRefusedError``.

    This is the second shape -- what a host that re-implements the
    gate's contract without importing the wiring raises.  It is
    declared here so this file can exercise the queue's contract
    without importing the wiring (the queue must not drag the wiring
    in; the wiring imports the hold, and the hold must not drag the
    queue in).
    """

    def __init__(self, message, reason=None):
        super().__init__(message)
        self.reason = reason


class _LyingGate:
    """A gate whose two forms answer the SAME question DIFFERENTLY.

    ``queue_allowed`` says "allowed"; ``require_queue_allowed`` raises.
    A host gate whose two forms disagree is a **host's** bug -- but the
    queue must not be more permissive because it happened to ask the
    permissive one.
    """

    def __init__(self):
        self.asked = 0

    def queue_allowed(self, job_id, action, *, now=None):
        return True

    def require_queue_allowed(self, job_id, action, *, now=None):
        self.asked += 1
        raise RefusalRefusedError(
            "this action is refused", reason="blocked_by_refusal"
        )


class _BooleanOnlyGate:
    """A gate that offers ONLY the boolean form, and refuses.

    The boolean form carries no reason -- a refusal and a gate that
    cannot answer are both ``False`` -- so the queue must still name a
    real class in the trail's ``reason`` slot, and must still refuse.
    """

    def queue_allowed(self, job_id, action, *, now=None):
        return False


class _BrokenGate:
    """A gate that CANNOT ANSWER.

    It refuses nothing in particular: it is broken, not refusing.  The
    raising form books no row for it, so the batch form must book no
    row either -- a ``job.rejected`` row would put a refusal in the
    trail that never happened.
    """

    def require_queue_allowed(self, job_id, action, *, now=None):
        raise RuntimeError("the gate is broken")


def _reserved_with_gate(gate):
    """A job that is enqueued and RESERVED, with the gate installed."""
    jq = JobQueue(refusal_gate=gate)
    _enqueue(jq, seq=1)
    _dequeue_around_the_gate(jq)
    return jq


def test_the_batch_form_refuses_what_the_raising_form_refuses():
    """The defect: the batch form re-dispatched a REFUSED action.

    The gate offers both methods.  The raising one refuses; the
    boolean one allows.  The batch form took the boolean answer and put
    the job back to ``ready`` -- so the refused action was offered
    again.
    """
    jq = _reserved_with_gate(_LyingGate())
    record = jq.retry_allowed("j-1", 3)
    assert record is None, (
        "the batch form re-dispatched an action the raising form refuses"
    )
    assert jq.job("j-1").state == "reserved", (
        "the refused action went back to 'ready' and would be offered again"
    )


def test_the_batch_form_leaves_a_refused_job_where_it_was():
    """The job keeps its state and its attempts."""
    jq = _reserved_with_gate(_LyingGate())
    before = jq.job("j-1")
    jq.retry_allowed("j-1", 3)
    after = jq.job("j-1")
    assert after.state == before.state
    assert after.attempts == before.attempts


def test_the_two_forms_agree_on_a_gate_that_offers_only_the_raising_one():
    """The control: a gate with ONE form is unchanged."""
    jq = _reserved_with_gate(_RefusingGate())
    assert jq.retry_allowed("j-1", 3) is None
    assert jq.job("j-1").state == "reserved"


def test_a_boolean_only_gate_still_refuses():
    """A gate with no raising form must not be treated as allowing."""
    jq = _reserved_with_gate(_BooleanOnlyGate())
    assert jq.retry_allowed("j-1", 3) is None
    assert jq.job("j-1").state == "reserved"


def test_an_allowed_gate_still_re_dispatches():
    """The control: the fix must not break the ordinary path."""
    jq = _reserved_with_gate(_CountingGate())
    record = jq.retry_allowed("j-1", 3)
    assert record is not None, "an allowed job was not re-dispatched"
    assert jq.job("j-1").state == "ready"


def test_the_batch_form_asks_the_gate_exactly_once_on_the_refused_path():
    """One job is ONE check, on the refused path too.

    The refused path returns before the write, so a double ask would
    not show up in the trail's event count on that path -- but it would
    show up in the GATE's own count, and it would double the gate's
    cost for a job that was never re-dispatched.
    """
    gate = _LyingGate()
    jq = JobQueue(refusal_gate=gate)
    _enqueue(jq, seq=1)
    asked_after_dequeue = _dequeue_around_the_gate(jq)
    jq.retry_allowed("j-1", 3)
    assert getattr(gate, "asked", 0) - asked_after_dequeue == 1, (
        "the gate was asked more than once for one job"
    )


# ---------------------------------------------------------------------------
# 17c. what the batch form BOOKS
# ---------------------------------------------------------------------------
#
# A refusal is booked in the queue's own trail, so the trail names the
# refused re-dispatch.  Two rules follow from that, and the batch form
# broke both:
#
# 1. A **broken** gate books no row.  It refuses nothing in particular,
#    so a ``job.rejected`` row would put a refusal in the trail that
#    never happened.  The raising form already books no row for it.
# 2. A booked row names a **real class** in its ``reason`` slot.  The
#    boolean form carries no reason, and the batch form had nothing to
#    put there -- so it put the class name of the MISSING exception
#    there, and the row read ``"NoneType"``.


def _rejected_rows(jq):
    """The ``job.rejected`` rows in the queue's own trail."""
    return [
        row for row in jq.audit_log()
        if row.get("kind") == "job.rejected"
    ]


def _row_detail(row):
    """The payload of an audit row.

    An audit row is ``{schema, kind, module, detail, seq}`` -- the
    fields a reader of the trail actually looks at live in ``detail``,
    so a test that reads ``row["job_id"]`` is reading a key that is not
    there.
    """
    detail = row.get("detail")
    return detail if isinstance(detail, dict) else row


def test_a_broken_gate_books_no_rejected_row_on_the_batch_form():
    """A gate that cannot answer is not a refusal.

    The raising form books no row for a broken gate.  The batch form
    did: the trail showed a refusal that never happened, and a reader
    of the trail could not tell it from a real one.
    """
    jq = _reserved_with_gate(_BrokenGate())
    assert jq.retry_allowed("j-1", 3) is None
    assert _rejected_rows(jq) == [], (
        "the batch form booked a rejection for a gate that refused "
        "nothing in particular"
    )


def test_a_refused_row_names_a_reason_that_is_not_the_absence_of_one():
    """The ``reason`` slot must name a real class.

    The boolean form refuses without saying why, so there was no reason
    to hand back -- and the row put the class name of the MISSING
    exception there, which read ``"NoneType"``.
    """
    jq = _reserved_with_gate(_BooleanOnlyGate())
    assert jq.retry_allowed("j-1", 3) is None
    rows = _rejected_rows(jq)
    assert len(rows) == 1, (
        "the refusal was not booked in the queue's own trail: %r" % (rows,)
    )
    reason = _row_detail(rows[0]).get("reason")
    assert reason and reason != "NoneType", (
        "the refused row names the absence of a reason, not a class: %r"
        % (reason,)
    )


def test_a_refused_row_still_names_the_job_and_the_action():
    """The row names WHO was refused and WHAT was refused."""
    jq = _reserved_with_gate(_LyingGate())
    assert jq.retry_allowed("j-1", 3) is None
    rows = _rejected_rows(jq)
    assert len(rows) == 1, (
        "the refusal was not booked in the queue's own trail: %r" % (rows,)
    )
    detail = _row_detail(rows[0])
    assert detail.get("job_id") == "j-1", rows[0]
    assert detail.get("action") == "send_email", rows[0]


def test_the_raising_form_and_the_batch_form_book_the_same_rows():
    """The two forms must agree about the TRAIL, not only the outcome.

    The trail is the record of what happened.  If the two forms book
    different rows for the same refusal, then a reader of the trail
    cannot tell which form a caller used -- and the batch form is the
    one that sweeps many jobs, so its rows are the ones an operator
    would read.
    """
    jq = _reserved_with_gate(_RefusalRaisingGate())
    assert jq.retry_allowed("j-1", 3) is None
    batch_rows = _rejected_rows(jq)

    jq2 = _reserved_with_gate(_RefusalRaisingGate())
    with pytest.raises(job_queue.JobQueueError):
        jq2.retry("j-1", 3)
    raising_rows = _rejected_rows(jq2)

    assert len(batch_rows) == len(raising_rows) == 1, (
        "the two forms booked different numbers of rows: batch=%r "
        "raising=%r" % (batch_rows, raising_rows)
    )
    assert batch_rows[0].get("kind") == raising_rows[0].get("kind")
    batch_detail = _row_detail(batch_rows[0])
    raising_detail = _row_detail(raising_rows[0])
    assert batch_detail.get("job_id") == raising_detail.get("job_id")
    assert batch_detail.get("action") == raising_detail.get("action")


def test_the_raising_form_books_exactly_ONE_row_for_one_refusal():
    """One refusal is ONE row.

    The raising form books the refusal inside its own ``except``
    block, and then the exception continues into the ``except
    JobQueueError`` handler further out -- which books a SECOND
    ``job.rejected`` row for the same refusal, with a different shape
    (no ``action``, no ``refusal_reason``).

    So a reader of the trail saw two rejections for one refused
    re-dispatch, and the two rows disagreed about what happened: only
    one of them named the ACTION, and only one of them named the
    reason.  Which one a reader picked determined what they learned.

    Measured 2026-11-25 on the tree as the chain-close slice left it::

        raising form, one refused job:
          job.rejected {'reason': 'RefusalRefusedError',
                        'refusal_reason': 'blocked_by_refusal',
                        'job_id': 'j1', 'action': 'send_email'}
          job.rejected {'reason': 'RefusalRefusedError', 'job_id': 'j1'}

    Two rows, one refusal, two different stories.
    """
    jq = _reserved_with_gate(_RefusalRaisingGate())
    with pytest.raises(job_queue.JobQueueError):
        jq.retry("j-1", 3)
    rows = _rejected_rows(jq)
    assert len(rows) == 1, (
        "one refusal booked %d rows: %r" % (len(rows), rows)
    )
    detail = _row_detail(rows[0])
    assert detail.get("action") == "send_email", (
        "the surviving row must be the one that names the action: %r"
        % (detail,)
    )
    assert detail.get("refusal_reason") == "blocked_by_refusal", (
        "the surviving row must be the one that names the reason: %r"
        % (detail,)
    )


def test_a_plain_queue_error_gate_is_booked_the_same_way_on_both_forms():
    """A host gate whose vocabulary the queue does not recognise.

    ``_is_refusal`` draws the line between a refusal and a broken gate
    on the error's VOCABULARY: a ``reason`` attribute whose value is
    one of the hold's ``blocked_*`` reasons, or the class name
    ``RefusalRefusedError``.  A host gate that raises the queue's own
    ``JobQueueError`` -- which is what a host that does not import the
    wiring has to hand, since ``JobQueueError`` is the base class of
    this module's taxonomy -- falls OUTSIDE that vocabulary.

    So the queue cannot tell it from a broken gate.  And that is the
    only consistent answer: **both** forms must treat it the same way.
    Before the fix they did not -- the raising form booked a rejection
    (through the generic ``except JobQueueError`` handler) and the
    batch form booked none (it asks ``_is_refusal``).

    Measured 2026-11-25 on the tree as the chain-close slice left it::

        plain JobQueueError gate   raising rows=1  batch rows=0

    So the trail said the two forms saw different events, for one
    refusal.

    The rule this pins: the two forms book the SAME rows, whatever
    vocabulary the host's gate uses.  When the vocabulary is
    unrecognised, that means **neither** books a row -- because an
    unrecognised exception is a gate the queue cannot answer, and a
    gate that cannot answer refuses nothing in particular.
    """
    jq = _reserved_with_gate(_PlainQueueErrorGate())
    with pytest.raises(job_queue.JobQueueError):
        jq.retry("j-1", 3)
    raising_rows = _rejected_rows(jq)

    jq2 = _reserved_with_gate(_PlainQueueErrorGate())
    assert jq2.retry_allowed("j-1", 3) is None
    batch_rows = _rejected_rows(jq2)

    assert len(raising_rows) == len(batch_rows), (
        "the two forms booked different rows for one refusal: "
        "raising=%r batch=%r" % (raising_rows, batch_rows)
    )
    assert raising_rows == [], (
        "a gate whose vocabulary the queue cannot recognise must book "
        "no row at all: it refuses nothing in particular"
    )


def test_the_dead_path_books_the_same_rows_on_both_forms():
    """A job that runs out of retry budget is a rejection on BOTH forms.

    The raising form raised ``MaxRetriesExceededError``, and the
    generic handler booked a ``job.rejected`` row for it.  The batch
    form returned ``None`` -- "not re-dispatched" -- and booked
    NOTHING, so the trail said the two forms saw different events for
    the same job reaching the end of its budget.

    Measured 2026-11-25 on the tree as the chain-close slice left it::

        RAISING dead  rejected rows: [('job.rejected',
                                        {'reason': 'MaxRetriesExceededError',
                                         'job_id': 'j-1'})]
        BATCH   dead  rejected rows: []

    The ``job.dead`` row is booked on both forms, so the trail did
    name the death -- but the REJECTION was on one form only, and the
    rejection is what says the job was not re-dispatched.
    """
    jq = _dead_job()
    with pytest.raises(MaxRetriesExceededError):
        jq.retry("j-1", 5)
    raising_rows = _rejected_rows(jq)

    jq2 = _dead_job()
    assert jq2.retry_allowed("j-1", 5) is None
    batch_rows = _rejected_rows(jq2)

    assert len(raising_rows) == len(batch_rows) == 1, (
        "the two forms booked different rows for the same dead job: "
        "raising=%r batch=%r" % (raising_rows, batch_rows)
    )
    assert _row_detail(batch_rows[0]).get("reason") == "MaxRetriesExceededError"


def _dead_job():
    """A job that has used up its retry budget."""
    jq = JobQueue()
    _enqueue(jq, seq=1, max_retries=2)
    jq.dequeue("w-1", "default", 2)   # attempt 1
    jq.retry("j-1", 3)                # 1 < 2: requeued
    jq.dequeue("w-1", "default", 4)   # attempt 2
    return jq


class _RefusalRaisingGate:
    """A gate that refuses the way the wiring's own gate refuses.

    It raises the shape ``_is_refusal`` recognises -- the class name
    ``RefusalRefusedError`` and the ``reason`` attribute -- so the row
    can name both the class and the hold's reason slug.
    """

    def __init__(self):
        self.asked = 0

    def require_queue_allowed(self, job_id, action, *, now=None):
        self.asked += 1
        raise RefusalRefusedError(
            "this action is refused", reason="blocked_by_refusal"
        )


class _PlainQueueErrorGate:
    """A gate that refuses with the queue's OWN base error.

    A host that does not import the wiring has nothing else to raise:
    ``JobQueueError`` is the base class of this module's taxonomy, and
    it is what a host reading this module's docstring would reach for.
    """

    def __init__(self):
        self.asked = 0

    def require_queue_allowed(self, job_id, action, *, now=None):
        self.asked += 1
        raise job_queue.JobQueueError("this action is refused")


# ---------------------------------------------------------------------------
# 15. main() self-check
# ---------------------------------------------------------------------------


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, job_queue.__file__],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "job-queue OK" in proc.stdout
