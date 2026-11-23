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
        def __init__(self):
            self.asked = 0

        def require_queue_allowed(self, job_id, action, *, now=None):
            self.asked += 1
            raise AssertionError("the gate must not be asked by dead()")

    jq = JobQueue(refusal_gate=RefusingGate())
    _enqueue(jq, seq=1)
    jq.dequeue("w-1", "default", 2)
    jq.dead("j-1", 3)
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
    jq.dequeue("w-1", "default", 2)
    assert jq.retry_allowed("j-1", 3) is None
    assert jq.job("j-1").state == "reserved"


def test_retry_allowed_does_not_raise_on_a_refusal():
    """The whole point: one refused job must not abandon the sweep."""
    jq = JobQueue(refusal_gate=_RefusingGate())
    _enqueue(jq, seq=1)
    jq.dequeue("w-1", "default", 2)
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
    """
    gate = _RefusingGate()
    jq = JobQueue(refusal_gate=gate)
    _enqueue(jq, seq=1)
    jq.dequeue("w-1", "default", 2)
    jq.retry_allowed("j-1", 3)
    assert gate.asked == 1


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
    jq.dequeue("w-1", "default", 2)
    rec = jq.retry_allowed("j-1", 3)
    assert rec is not None
    assert gate.asked == 1, (
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
