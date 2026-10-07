"""Targeted tests for the priority_queue ledger."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import priority_queue as pq_mod
from priority_queue import (
    AuditKindError,
    BadDigestError,
    BadItemError,
    BadPriorityError,
    DuplicateItemError,
    EmptyQueueError,
    PriorityQueue,
    SeqOrderError,
    priority_queue_audit_event,
)

MODULE_FILE = Path(pq_mod.__file__)
VALID_DIGEST = "sha256:" + "ab" * 32


def test_version_and_schema_pins():
    assert pq_mod.PRIORITY_QUEUE_VERSION == "priority-queue.v1"
    assert pq_mod.PRIORITY_QUEUE_SCHEMA == "northstar.priority-queue.v1"
    assert pq_mod.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(pq_mod._KINDS) == {
        "priority.pushed",
        "priority.popped",
        "priority.rejected",
    }


def test_stdlib_only():
    tree = ast.parse(MODULE_FILE.read_text())
    allowed = {
        "heapq", "hashlib", "threading", "dataclasses", "typing",
        "__future__", "json", "canonical_json", "northstar_agent_runtime",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_push_roundtrip_and_verify():
    q = PriorityQueue()
    rec = q.push("job-1", 10, 1, VALID_DIGEST)
    assert rec.verify()
    assert rec.item_id == "job-1"
    assert rec.priority == 10
    assert rec.order == 1
    assert rec.payload_digest == VALID_DIGEST
    assert rec.schema == "northstar.priority-queue.v1"
    assert q.push_record("job-1") == rec
    # Tampered record must not verify.
    import dataclasses
    tampered = dataclasses.replace(rec, priority=1)
    assert not tampered.verify()


def test_duplicate_push_refused_and_seq_burned():
    q = PriorityQueue()
    q.push("a", 1, 1)
    with pytest.raises(DuplicateItemError):
        q.push("a", 2, 2)
    kinds = [e["kind"] for e in q.audit_log()]
    assert kinds == ["priority.pushed", "priority.rejected"]
    # Failed mutation consumed seq 2: a rewind to 2 raises without burning,
    # but a fresh seq 3 must be accepted as the next valid one.
    with pytest.raises(SeqOrderError):
        q.push("b", 1, 2)
    rec = q.push("b", 1, 3)
    assert rec.verify()


def test_bad_input_table():
    q = PriorityQueue()
    seq = 1
    bad_items = ["", "has space", "a" * 257, 123, None]
    for item in bad_items:
        with pytest.raises(BadItemError):
            q.push(item, 1, seq)
            seq += 1
        seq += 1
    bad_priorities = [True, 1.5, "3", None, 1 << 54]
    for prio in bad_priorities:
        with pytest.raises(BadPriorityError):
            q.push("x", prio, seq)
        seq += 1
    with pytest.raises(BadDigestError):
        q.push("x", 1, seq, "nope")
    seq += 1
    # Rejected rows were booked for each failure.
    kinds = [e["kind"] for e in q.audit_log()]
    assert all(k == "priority.rejected" for k in kinds)
    assert len(kinds) == len(bad_items) + len(bad_priorities) + 1
    assert q.size(seq) == 0


def test_pop_order_lowest_priority_first():
    q = PriorityQueue()
    q.push("low", 10, 1)
    q.push("high", 1, 2)
    q.push("mid", 5, 3)
    first = q.pop(4)
    assert first.item_id == "high" and first.verify()
    second = q.pop(5)
    assert second.item_id == "mid" and second.verify()
    third = q.pop(6)
    assert third.item_id == "low" and third.verify()
    assert first.push_seq == 2 and second.push_seq == 3 and third.push_seq == 1


def test_pop_fifo_tie_break():
    q = PriorityQueue()
    q.push("first", 5, 1)
    q.push("second", 5, 2)
    q.push("third", 5, 3)
    assert q.pop(4).item_id == "first"
    assert q.pop(5).item_id == "second"
    assert q.pop(6).item_id == "third"


def test_pop_empty_fail_closed():
    q = PriorityQueue()
    with pytest.raises(EmptyQueueError):
        q.pop(1)
    kinds = [e["kind"] for e in q.audit_log()]
    assert kinds == ["priority.rejected"]
    assert q.stats(2)["pending"] == 0


def test_peek_is_pure_read():
    q = PriorityQueue()
    # Empty peek is data, not a raise.
    empty = q.peek(1)
    assert not empty.found and empty.item_id == "" and empty.verify()
    q.push("b", 9, 2)
    q.push("a", 3, 3)
    head = q.peek(4)
    assert head.found and head.item_id == "a" and head.verify()
    # Peek consumed no seq: pop at 4 must still be valid, peek left no rows.
    rec = q.pop(4)
    assert rec.item_id == "a"
    kinds = [e["kind"] for e in q.audit_log()]
    assert kinds == ["priority.pushed", "priority.pushed", "priority.popped"]
    # Still two pending before the pop, size is a pure read too.
    assert q.size(5) == 1
    with pytest.raises(SeqOrderError):
        q.peek(-1)
    with pytest.raises(SeqOrderError):
        q.size(True)


def test_seq_ordering_rewind_and_bool():
    q = PriorityQueue()
    q.push("a", 1, 1)
    for bad in (1, 0, True, "2", 1.0, -1):
        with pytest.raises(SeqOrderError):
            q.push("b", 1, bad)
        with pytest.raises(SeqOrderError):
            q.pop(bad)
    rec = q.push("b", 2, 2)
    assert rec.verify()


def test_audit_shapes_and_banned_keys():
    q = PriorityQueue()
    rec = q.push("a", 1, 1)
    popped = q.pop(2)
    log = q.audit_log()
    assert len(log) == 2
    for event in log:
        assert event["schema"] == "audit.ndjson/1"
        assert event["module"] == "priority-queue.v1"
        assert "payload" not in event["detail"]
    assert log[0]["kind"] == "priority.pushed"
    assert log[0]["detail"]["item_id"] == "a"
    assert log[0]["detail"]["digest"] == rec.digest
    assert log[1]["kind"] == "priority.popped"
    assert log[1]["detail"]["digest"] == popped.digest
    with pytest.raises(AuditKindError):
        priority_queue_audit_event("nope", {}, 3)
    with pytest.raises(AuditKindError):
        priority_queue_audit_event("priority.pushed", {"payload": "x"}, 3)


def test_stats_views_and_item_order():
    q = PriorityQueue()
    q.push("c", 30, 1)
    q.push("a", 10, 2)
    q.push("b", 20, 3)
    stats = q.stats(4)
    assert stats == {"pending": 3, "pushes": 3, "pops": 0, "last_seq": 3}
    assert q.item_ids() == ("a", "b", "c")
    q.pop(5)
    assert q.stats(6)["pops"] == 1
    assert q.push_record("a") is None
    assert q.push_record("b") is not None


def test_cross_instance_digest_determinism():
    q1, q2 = PriorityQueue(), PriorityQueue()
    r1 = q1.push("job", 7, 1, VALID_DIGEST)
    r2 = q2.push("job", 7, 1, VALID_DIGEST)
    assert r1.digest == r2.digest
    p1 = q1.pop(2)
    p2 = q2.pop(2)
    assert p1.digest == p2.digest
    # Different priority -> different pin.
    q3 = PriorityQueue()
    r3 = q3.push("job", 8, 1, VALID_DIGEST)
    assert r3.digest != r1.digest


def test_negative_priorities_and_fifo_readd():
    q = PriorityQueue()
    q.push("neg", -5, 1)
    q.push("zero", 0, 2)
    q.push("pos", 5, 3)
    assert q.pop(4).item_id == "neg"
    assert q.pop(5).item_id == "zero"
    # A re-pushed id is a fresh record (retirement-free bookkeeping).
    rec = q.push("neg", 100, 6)
    assert rec.verify() and rec.order == 6
    assert q.pop(7).item_id == "pos"
    assert q.pop(8).item_id == "neg"


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE_FILE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "priority-queue OK" in proc.stdout
