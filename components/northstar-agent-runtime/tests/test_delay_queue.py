"""Tests for delay_queue: delayed-task delivery bookkeeping."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import delay_queue
from delay_queue import (
    AuditKindError,
    BadDelayError,
    BadDigestError,
    BadReasonError,
    BadTaskError,
    CancelRecord,
    DelayQueue,
    DelayQueueError,
    DuplicateTaskError,
    PollReport,
    ScheduleRecord,
    SeqOrderError,
    UnknownTaskError,
    delay_queue_audit_event,
)


def _digest(v: str) -> str:
    return delay_queue._pin("value", v)


_GOOD_DIGEST = "sha256:" + "ab" * 32


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert delay_queue.DELAY_QUEUE_VERSION == "delay-queue.v1"
    assert delay_queue.DELAY_QUEUE_SCHEMA == "northstar.delay-queue.v1"
    assert delay_queue.AUDIT_SCHEMA == "audit.ndjson/1"
    dq = DelayQueue()
    assert dq.stats().schema == delay_queue.DELAY_QUEUE_SCHEMA


# ---------------------------------------------------------------------------
# 2. stdlib-only
# ---------------------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(Path(delay_queue.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing",
               "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 3. schedule roundtrip + verify
# ---------------------------------------------------------------------------


def test_schedule_roundtrip_and_verify():
    dq = DelayQueue()
    rec = dq.schedule("t-1", _GOOD_DIGEST, 5, 1)
    assert isinstance(rec, ScheduleRecord)
    assert rec.ready_at == 6
    assert rec.verify()
    assert rec.schema == delay_queue.DELAY_QUEUE_SCHEMA
    view = dq.task("t-1")
    assert view is not None
    assert view.ready_at == 6 and view.delay_seqs == 5
    assert dq.task("missing") is None


# ---------------------------------------------------------------------------
# 4. duplicate / retired refusal
# ---------------------------------------------------------------------------


def test_schedule_duplicate_and_retired_refused():
    dq = DelayQueue()
    dq.schedule("t-1", _GOOD_DIGEST, 1, 1)
    with pytest.raises(DuplicateTaskError):
        dq.schedule("t-1", _GOOD_DIGEST, 1, 2)
    dq.cancel("t-1", 3)
    with pytest.raises(DuplicateTaskError):
        dq.schedule("t-1", _GOOD_DIGEST, 1, 4)


# ---------------------------------------------------------------------------
# 5. bad-input table
# ---------------------------------------------------------------------------


def test_schedule_bad_inputs():
    dq = DelayQueue()
    seq = [0]

    def nxt():
        seq[0] += 1
        return seq[0]

    bad_ids = ["", "   ", 1, True, None, b"t"]
    bad_digests = ["x", "sha256:" + "zz" * 32, 1, True, None]
    bad_delays = [0, -1, True, 1.5, "5", None]
    for tid in bad_ids:
        with pytest.raises(BadTaskError):
            dq.schedule(tid, _GOOD_DIGEST, 1, nxt())
    for d in bad_digests:
        with pytest.raises(BadDigestError):
            dq.schedule("t-bad", d, 1, nxt())
    for d in bad_delays:
        with pytest.raises(BadDelayError):
            dq.schedule("t-bad", _GOOD_DIGEST, d, nxt())


# ---------------------------------------------------------------------------
# 6. poll before due -> empty
# ---------------------------------------------------------------------------


def test_poll_before_due_is_empty():
    dq = DelayQueue()
    dq.schedule("t-1", _GOOD_DIGEST, 5, 1)
    assert dq.poll(2).due == ()
    assert dq.poll(5).due == ()


# ---------------------------------------------------------------------------
# 7. poll at / after due -> contains
# ---------------------------------------------------------------------------


def test_poll_at_due_contains_task():
    dq = DelayQueue()
    dq.schedule("t-1", _GOOD_DIGEST, 5, 1)
    dq.schedule("t-2", _GOOD_DIGEST, 2, 2)
    report = dq.poll(6)
    assert isinstance(report, PollReport)
    assert report.due == ("t-1", "t-2")  # sorted, deterministic
    assert dq.poll(3).due == ()  # t-2 ready_at=4, nothing due yet
    assert dq.poll(4).due == ("t-2",)


# ---------------------------------------------------------------------------
# 8. poll is a pure read view
# ---------------------------------------------------------------------------


def test_poll_is_pure_read():
    dq = DelayQueue()
    dq.schedule("t-1", _GOOD_DIGEST, 1, 1)
    audit_before = dq.audit_log()
    report = dq.poll(100)
    assert report.due == ("t-1",)
    # reading at the same seq is fine and writes nothing
    assert dq.poll(100).due == ("t-1",)
    assert dq.audit_log() == audit_before
    assert dq.pending() == ("t-1",)


# ---------------------------------------------------------------------------
# 9. cancel roundtrip + verify
# ---------------------------------------------------------------------------


def test_cancel_roundtrip_and_verify():
    dq = DelayQueue()
    dq.schedule("t-1", _GOOD_DIGEST, 1, 1)
    rec = dq.cancel("t-1", 2, "superseded")
    assert isinstance(rec, CancelRecord)
    assert rec.verify()
    assert dq.task("t-1") is None
    assert dq.pending() == ()
    assert dq.poll(1000).due == ()


# ---------------------------------------------------------------------------
# 10. cancel unknown / double-cancel
# ---------------------------------------------------------------------------


def test_cancel_unknown_and_double_refused():
    dq = DelayQueue()
    with pytest.raises(UnknownTaskError):
        dq.cancel("ghost", 1)
    dq.schedule("t-1", _GOOD_DIGEST, 1, 2)
    dq.cancel("t-1", 3)
    with pytest.raises(UnknownTaskError):
        dq.cancel("t-1", 4)
    with pytest.raises(BadReasonError):
        dq.cancel("t-x", 5, reason=123)


# ---------------------------------------------------------------------------
# 11. seq ordering
# ---------------------------------------------------------------------------


def test_seq_ordering():
    dq = DelayQueue()
    dq.schedule("t-1", _GOOD_DIGEST, 1, 1)
    with pytest.raises(SeqOrderError):
        dq.schedule("t-2", _GOOD_DIGEST, 1, 1)  # rewind
    with pytest.raises(SeqOrderError):
        dq.schedule("t-2", _GOOD_DIGEST, 1, True)
    with pytest.raises(SeqOrderError):
        dq.schedule("t-2", _GOOD_DIGEST, 1, -1)
    with pytest.raises(SeqOrderError):
        dq.schedule("t-2", _GOOD_DIGEST, 1, 1.5)
    dq.schedule("t-2", _GOOD_DIGEST, 1, 2)


# ---------------------------------------------------------------------------
# 12. failed mutations consume seq + rejected audit
# ---------------------------------------------------------------------------


def test_failed_mutation_consumes_seq():
    dq = DelayQueue()
    dq.schedule("t-1", _GOOD_DIGEST, 1, 1)
    with pytest.raises(DuplicateTaskError):
        dq.schedule("t-1", _GOOD_DIGEST, 1, 2)
    kinds = [row["kind"] for row in dq.audit_log()]
    assert delay_queue.KIND_REJECTED in kinds
    # seq 2 was burned by the failed mutation
    with pytest.raises(SeqOrderError):
        dq.schedule("t-2", _GOOD_DIGEST, 1, 2)
    dq.schedule("t-2", _GOOD_DIGEST, 1, 3)


# ---------------------------------------------------------------------------
# 13. audit shapes + leak ban + bad kind
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    dq = DelayQueue()
    dq.schedule("t-1", _GOOD_DIGEST, 2, 1)
    dq.cancel("t-1", 2, "nope")
    kinds = [row["kind"] for row in dq.audit_log()]
    assert kinds == [
        delay_queue.KIND_SCHEDULED,
        delay_queue.KIND_CANCELLED,
    ]
    for row in dq.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "delay-queue.v1"
    ev = delay_queue_audit_event(
        delay_queue.KIND_SCHEDULED, {"task_id": "t", "payload_digest": "d"}, 9
    )
    assert ev["seq"] == 9
    with pytest.raises(AuditKindError):
        delay_queue_audit_event("nope", {}, 1)
    with pytest.raises(AuditKindError):
        delay_queue_audit_event(
            delay_queue.KIND_SCHEDULED, {"payload": b"x"}, 1
        )


# ---------------------------------------------------------------------------
# 14. views / stats
# ---------------------------------------------------------------------------


def test_views_and_stats():
    dq = DelayQueue()
    dq.schedule("b", _GOOD_DIGEST, 5, 1)
    dq.schedule("a", _GOOD_DIGEST, 3, 2)
    assert dq.pending() == ("a", "b")
    assert dq.due_ids(5) == ("a",)
    assert dq.due_ids(6) == ("a", "b")
    stats = dq.stats()
    assert (stats.scheduled, stats.cancelled) == (2, 0)
    dq.cancel("a", 3)
    stats = dq.stats()
    assert (stats.scheduled, stats.cancelled) == (2, 1)


# ---------------------------------------------------------------------------
# 15. main() self-check
# ---------------------------------------------------------------------------


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, "-m", "delay_queue"],
        cwd=Path(delay_queue.__file__).parent,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "delay-queue OK" in proc.stdout
