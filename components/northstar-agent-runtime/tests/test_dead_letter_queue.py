"""Tests for dead_letter_queue: failed-message lifecycle bookkeeping."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import dead_letter_queue
from dead_letter_queue import (
    BadConfigError,
    BadDigestError,
    BadMessageError,
    BadReasonError,
    DeadLetterQueue,
    DeadLetterQueueError,
    DiscardRecord,
    DuplicateMessageError,
    EnqueueRecord,
    MaxRetriesExceededError,
    RetryRecord,
    SeqOrderError,
    TerminalMessageError,
    UnknownMessageError,
    dead_letter_queue_audit_event,
)


def _digest(v: str) -> str:
    return dead_letter_queue._pin("value", v)


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert dead_letter_queue.DEAD_LETTER_QUEUE_VERSION == "dead-letter-queue.v1"
    assert dead_letter_queue.DEAD_LETTER_QUEUE_SCHEMA == (
        "northstar.dead-letter-queue.v1"
    )
    assert dead_letter_queue.AUDIT_SCHEMA == "audit.ndjson/1"
    dlq = DeadLetterQueue()
    assert dlq.stats().schema == dead_letter_queue.DEAD_LETTER_QUEUE_SCHEMA


# ---------------------------------------------------------------------------
# 2. stdlib-only
# ---------------------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(Path(dead_letter_queue.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing",
               "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 3. enqueue roundtrip
# ---------------------------------------------------------------------------


def test_enqueue_roundtrip():
    dlq = DeadLetterQueue()
    rec = dlq.enqueue("m-1", _digest("x"), 1, "worker crashed")
    assert isinstance(rec, EnqueueRecord)
    assert rec.attempts == 1 and rec.max_retries == 3
    assert rec.state == "active" and rec.verify()
    view = dlq.message("m-1")
    assert view is not None and view.attempts == 1
    assert view.payload_digest == _digest("x")
    assert dlq.pending() == ("m-1",)


# ---------------------------------------------------------------------------
# 4. enqueue bad inputs fail closed + seq consumed + rejected audit
# ---------------------------------------------------------------------------


def test_enqueue_bad_inputs():
    dlq = DeadLetterQueue()
    before = len(dlq.audit_log())
    for bad_id, bad_digest, bad_reason in [
        ("", _digest("x"), ""),
        ("  ", _digest("x"), ""),
        (True, _digest("x"), ""),
        ("m", "not-a-digest", ""),
        ("m", "SHA256:" + "ab" * 32, ""),
        ("m", "sha256:" + "zz" * 32, ""),
        ("m", _digest("x"), "r" * 1025),
        ("m", _digest("x"), 123),
    ]:
        with pytest.raises(DeadLetterQueueError):
            dlq.enqueue(bad_id, bad_digest, 1, bad_reason)
    assert len(dlq.audit_log()) > before
    kinds = {row["kind"] for row in dlq.audit_log()}
    assert "dead-letter.rejected" in kinds
    # failed mutations consumed seq 1: rewind raises bare
    with pytest.raises(SeqOrderError):
        dlq.enqueue("m-2", _digest("y"), 1)


# ---------------------------------------------------------------------------
# 5. duplicate enqueue refused; retired ids never recycle
# ---------------------------------------------------------------------------


def test_duplicate_and_retired_ids():
    dlq = DeadLetterQueue()
    dlq.enqueue("m-1", _digest("x"), 1)
    with pytest.raises(DuplicateMessageError):
        dlq.enqueue("m-1", _digest("x"), 2)
    dlq.discard("m-1", 3)
    with pytest.raises(DuplicateMessageError):
        dlq.enqueue("m-1", _digest("x"), 4)


# ---------------------------------------------------------------------------
# 6. retry increments attempts
# ---------------------------------------------------------------------------


def test_retry_roundtrip():
    dlq = DeadLetterQueue(max_retries=4)
    dlq.enqueue("m-1", _digest("x"), 1)
    rec = dlq.retry("m-1", 2)
    assert isinstance(rec, RetryRecord)
    assert rec.attempts == 2 and rec.max_retries == 4 and rec.verify()
    rec = dlq.retry("m-1", 3)
    assert rec.attempts == 3
    assert dlq.message("m-1").attempts == 3


# ---------------------------------------------------------------------------
# 7. retry unknown message
# ---------------------------------------------------------------------------


def test_retry_unknown():
    dlq = DeadLetterQueue()
    with pytest.raises(UnknownMessageError):
        dlq.retry("ghost", 1)


# ---------------------------------------------------------------------------
# 8. exceeding max_retries marks terminal; further retry refused
# ---------------------------------------------------------------------------


def test_max_retries_terminal():
    dlq = DeadLetterQueue(max_retries=2)
    dlq.enqueue("m-1", _digest("x"), 1)
    dlq.retry("m-1", 2)  # attempts == 2 == max_retries, allowed
    with pytest.raises(MaxRetriesExceededError):
        dlq.retry("m-1", 3)
    view = dlq.message("m-1")
    assert view is not None and view.state == "terminal"
    assert view.attempts == 2
    with pytest.raises(TerminalMessageError):
        dlq.retry("m-1", 4)
    assert dlq.pending() == ()


# ---------------------------------------------------------------------------
# 9. discard roundtrip, id retirement, unknown discard
# ---------------------------------------------------------------------------


def test_discard_roundtrip_and_unknown():
    dlq = DeadLetterQueue()
    dlq.enqueue("m-1", _digest("x"), 1)
    rec = dlq.discard("m-1", 2, "poison payload")
    assert isinstance(rec, DiscardRecord) and rec.verify()
    assert dlq.message("m-1") is None
    with pytest.raises(UnknownMessageError):
        dlq.discard("m-1", 3)
    with pytest.raises(UnknownMessageError):
        dlq.discard("never", 4)


# ---------------------------------------------------------------------------
# 10. seq discipline: rewind/bool/negative refused
# ---------------------------------------------------------------------------


def test_seq_discipline():
    dlq = DeadLetterQueue()
    dlq.enqueue("m-1", _digest("x"), 1)
    for bad in (1, 0, -5, True, 1.0, "2"):
        with pytest.raises(SeqOrderError):
            dlq.retry("m-1", bad)


# ---------------------------------------------------------------------------
# 11. failed mutation consumes seq
# ---------------------------------------------------------------------------


def test_failed_mutation_consumes_seq():
    dlq = DeadLetterQueue()
    dlq.enqueue("m-1", _digest("x"), 1)
    with pytest.raises(UnknownMessageError):
        dlq.retry("ghost", 2)
    # seq 2 is burned; only 3 may proceed
    with pytest.raises(SeqOrderError):
        dlq.retry("m-1", 2)
    rec = dlq.retry("m-1", 3)
    assert rec.attempts == 2


# ---------------------------------------------------------------------------
# 12. audit shapes + banned-key ban + bad kind
# ---------------------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    dlq = DeadLetterQueue()
    dlq.enqueue("m-1", _digest("x"), 1, "boom")
    dlq.retry("m-1", 2)
    dlq.discard("m-1", 3)
    kinds = [row["kind"] for row in dlq.audit_log()]
    assert kinds == [
        "dead-letter.enqueued",
        "dead-letter.retried",
        "dead-letter.discarded",
    ]
    for row in dlq.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert set(row["detail"]) & {"payload", "payload_bytes"} == set()
    with pytest.raises(dead_letter_queue.AuditKindError):
        dead_letter_queue_audit_event("nope", {}, 4)
    with pytest.raises(dead_letter_queue.AuditKindError):
        dead_letter_queue_audit_event(
            "dead-letter.enqueued", {"payload": b"x"}, 4
        )


# ---------------------------------------------------------------------------
# 13. views and stats
# ---------------------------------------------------------------------------


def test_views_and_stats():
    dlq = DeadLetterQueue()
    assert dlq.message("absent") is None
    dlq.enqueue("m-1", _digest("x"), 1)
    dlq.enqueue("m-2", _digest("y"), 2)
    assert dlq.pending() == ("m-1", "m-2")
    dlq.retry("m-1", 3)
    stats = dlq.stats()
    assert (stats.enqueued, stats.retried, stats.active, stats.discarded) == (
        2, 1, 2, 0,
    )
    with pytest.raises(BadMessageError):
        dlq.message(123)


# ---------------------------------------------------------------------------
# 14. bad constructor config
# ---------------------------------------------------------------------------


def test_bad_config():
    for bad in (0, -1, True, "3", 65):
        with pytest.raises(BadConfigError):
            DeadLetterQueue(max_retries=bad)


# ---------------------------------------------------------------------------
# 15. main() self-check
# ---------------------------------------------------------------------------


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, dead_letter_queue.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "dead-letter-queue OK" in result.stdout
