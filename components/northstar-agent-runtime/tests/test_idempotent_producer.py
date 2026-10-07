"""Tests for idempotent_producer: Kafka-style exactly-once send bookkeeping."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import idempotent_producer
from idempotent_producer import (
    AuditKindError,
    BadDigestError,
    BadPartitionError,
    BadProducerSeqError,
    BadTopicError,
    IdempotentProducer,
    IdempotentProducerError,
    OutOfOrderError,
    SeqOrderError,
    idempotent_producer_audit_event,
)


def _digest(v: str) -> str:
    return idempotent_producer._pin("value", v)


def _prod(pid: str = "pid-1") -> IdempotentProducer:
    return IdempotentProducer(pid)


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert idempotent_producer.IDEMPOTENT_PRODUCER_VERSION == "idempotent-producer.v1"
    assert (
        idempotent_producer.IDEMPOTENT_PRODUCER_SCHEMA
        == "northstar.idempotent-producer.v1"
    )
    assert idempotent_producer.AUDIT_SCHEMA == "audit.ndjson/1"
    rec = _prod().send("t", 0, 0, _digest("v"), 1)
    assert rec.version == idempotent_producer.IDEMPOTENT_PRODUCER_VERSION
    assert rec.schema == idempotent_producer.IDEMPOTENT_PRODUCER_SCHEMA


# ---------------------------------------------------------------------------
# 2. stdlib-only
# ---------------------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(Path(idempotent_producer.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing",
               "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 3. main() self-check
# ---------------------------------------------------------------------------


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, idempotent_producer.__file__],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "idempotent-producer OK" in proc.stdout


# ---------------------------------------------------------------------------
# 4. send roundtrip
# ---------------------------------------------------------------------------


def test_send_roundtrip_appended():
    prod = _prod()
    rec = prod.send("orders", 0, 0, _digest("v1"), 1)
    assert rec.verdict == "appended"
    assert rec.send_id == "send-1"
    assert rec.topic == "orders" and rec.partition == 0
    assert rec.producer_seq == 0
    assert rec.payload_digest == _digest("v1")
    assert rec.verify()


# ---------------------------------------------------------------------------
# 5. duplicate dedupe: same seq is data, not re-appended
# ---------------------------------------------------------------------------


def test_duplicate_deduped_not_reappended():
    prod = _prod()
    prod.send("orders", 0, 0, _digest("v1"), 1)
    dup = prod.send("orders", 0, 0, _digest("v1"), 2)
    assert dup.verdict == "duplicate"
    assert dup.verify()
    assert prod.stats()["appended"] == 1  # no re-append
    kinds = [e["kind"] for e in prod.audit_log()]
    assert "idempotent-producer.deduplicated" in kinds


# ---------------------------------------------------------------------------
# 6. sequence(): next assignable producer seq (pure read)
# ---------------------------------------------------------------------------


def test_sequence_next_assignable():
    prod = _prod()
    assert prod.sequence("orders", 0, 1).next_seq == 0
    prod.send("orders", 0, 0, _digest("v"), 2)
    prod.send("orders", 0, 1, _digest("v"), 3)
    assert prod.sequence("orders", 0, 4).next_seq == 2
    # read consumes nothing: ledger seq still 3
    with pytest.raises(SeqOrderError):
        prod.send("orders", 0, 2, _digest("v"), 3)  # rewind -> refused


# ---------------------------------------------------------------------------
# 7. dedupe(): preview verdict as data, books nothing
# ---------------------------------------------------------------------------


def test_dedupe_preview_as_data():
    prod = _prod()
    prod.send("orders", 0, 0, _digest("v"), 1)
    assert prod.dedupe("orders", 0, 1, 2).verdict == "new"
    assert prod.dedupe("orders", 0, 0, 3).verdict == "duplicate"
    assert prod.dedupe("orders", 0, 9, 4).verdict == "out-of-order"
    assert len(prod.audit_log()) == 1  # reads book nothing


# ---------------------------------------------------------------------------
# 8. out-of-order gap is fail-closed
# ---------------------------------------------------------------------------


def test_out_of_order_gap_fail_closed():
    prod = _prod()
    prod.send("orders", 0, 0, _digest("v"), 1)
    with pytest.raises(OutOfOrderError):
        prod.send("orders", 0, 5, _digest("v"), 2)
    kinds = [e["kind"] for e in prod.audit_log()]
    assert "idempotent-producer.rejected" in kinds
    # failed mutation consumed its seq: seq 2 cannot be reused
    with pytest.raises(SeqOrderError):
        prod.send("orders", 0, 1, _digest("v"), 2)


# ---------------------------------------------------------------------------
# 9. bad-input table (fail-closed, seq consumed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "topic,partition,producer_seq,digest,exc",
    [
        ("", 0, 0, "x", BadTopicError),
        (123, 0, 0, "x", BadTopicError),
        ("t", -1, 0, "x", BadPartitionError),
        ("t", 1024, 0, "x", BadPartitionError),
        ("t", True, 0, "x", BadPartitionError),
        ("t", 0, -1, "x", BadProducerSeqError),
        ("t", 0, True, "x", BadProducerSeqError),
        ("t", 0, 1.0, "x", BadProducerSeqError),
        ("t", 0, 0, "nope", BadDigestError),
        ("t", 0, 0, "sha256:zzzz", BadDigestError),
    ],
)
def test_bad_inputs_fail_closed(topic, partition, producer_seq, digest, exc):
    prod = _prod()
    n_before = len(prod.audit_log())
    with pytest.raises(exc):
        prod.send(topic, partition, producer_seq, digest, 1)
    assert len(prod.audit_log()) == n_before + 1
    assert prod.audit_log()[-1]["kind"] == "idempotent-producer.rejected"


# ---------------------------------------------------------------------------
# 10. ledger seq ordering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_seq", [0, -3, True, 1.5, "1", None])
def test_seq_ordering(bad_seq):
    prod = _prod()
    with pytest.raises(SeqOrderError):
        prod.send("t", 0, 0, _digest("v"), bad_seq)


def test_seq_rewind_refused():
    prod = _prod()
    prod.send("t", 0, 0, _digest("v"), 10)
    with pytest.raises(SeqOrderError):
        prod.send("t", 0, 1, _digest("v"), 10)


# ---------------------------------------------------------------------------
# 11. per-partition and per-topic independence
# ---------------------------------------------------------------------------


def test_partition_independence():
    prod = _prod()
    prod.send("t", 0, 0, _digest("a"), 1)
    prod.send("t", 0, 1, _digest("b"), 2)
    # partition 1 starts its own sequence at 0
    rec = prod.send("t", 1, 0, _digest("c"), 3)
    assert rec.verdict == "appended"
    assert prod.sequence("t", 0, 4).next_seq == 2
    assert prod.sequence("t", 1, 5).next_seq == 1
    # a gap on partition 1 does not disturb partition 0
    with pytest.raises(OutOfOrderError):
        prod.send("t", 1, 7, _digest("c"), 6)
    assert prod.send("t", 0, 2, _digest("d"), 7).verdict == "appended"


def test_topic_independence():
    prod = _prod()
    prod.send("a", 0, 0, _digest("x"), 1)
    rec = prod.send("b", 0, 0, _digest("y"), 2)
    assert rec.verdict == "appended"


# ---------------------------------------------------------------------------
# 12. stale (older-than-last) producer seq is a duplicate, not an error
# ---------------------------------------------------------------------------


def test_stale_seq_is_duplicate_data():
    prod = _prod()
    prod.send("t", 0, 0, _digest("a"), 1)
    prod.send("t", 0, 1, _digest("b"), 2)
    stale = prod.send("t", 0, 0, _digest("a"), 3)
    assert stale.verdict == "duplicate"
    assert prod.stats()["appended"] == 2


# ---------------------------------------------------------------------------
# 13. audit shapes, banned keys, bad kind
# ---------------------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    prod = _prod()
    prod.send("t", 0, 0, _digest("v"), 1)
    prod.send("t", 0, 0, _digest("v"), 2)
    with pytest.raises(OutOfOrderError):
        prod.send("t", 0, 9, _digest("v"), 3)
    kinds = [e["kind"] for e in prod.audit_log()]
    assert kinds == [
        "idempotent-producer.sent",
        "idempotent-producer.deduplicated",
        "idempotent-producer.rejected",
    ]
    for event in prod.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        banned = idempotent_producer._BANNED_AUDIT_KEYS
        assert not (set(event["detail"]) & banned), event["detail"]


def test_audit_bad_kind():
    with pytest.raises(AuditKindError):
        idempotent_producer_audit_event("bogus", {}, 1)
    with pytest.raises(SeqOrderError):
        idempotent_producer_audit_event("idempotent-producer.sent", {}, 0)


# ---------------------------------------------------------------------------
# 14. record verify() tamper detection
# ---------------------------------------------------------------------------


def test_record_verify_tamper():
    prod = _prod()
    rec = prod.send("t", 0, 0, _digest("v"), 1)
    assert rec.verify()
    import dataclasses

    forged = dataclasses.replace(rec, verdict="appended" if rec.verdict != "appended" else "duplicate")
    assert not forged.verify()


# ---------------------------------------------------------------------------
# 15. stats and audit_log views
# ---------------------------------------------------------------------------


def test_stats_and_audit_views():
    prod = _prod()
    prod.send("a", 0, 0, _digest("x"), 1)
    prod.send("a", 0, 1, _digest("y"), 2)
    prod.send("b", 2, 0, _digest("z"), 3)
    stats = prod.stats()
    assert stats["producer_id"] == "pid-1"
    assert stats["partitions"] == 2
    assert stats["sends"] == 3
    assert stats["appended"] == 3
    assert stats["schema"] == idempotent_producer.IDEMPOTENT_PRODUCER_SCHEMA
    assert len(prod.audit_log()) == 3


def test_bad_producer_id():
    with pytest.raises(IdempotentProducerError):
        IdempotentProducer("")
    with pytest.raises(IdempotentProducerError):
        IdempotentProducer(123)
