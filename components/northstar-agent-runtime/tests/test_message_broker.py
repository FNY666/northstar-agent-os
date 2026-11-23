"""Tests for message_broker.py (pytest style, matching sibling batch tests)."""

from __future__ import annotations

import ast
import subprocess
import sys

import pytest

import message_broker
from message_broker import (
    AuditKindError,
    BadAckError,
    BadGroupError,
    BadMessageError,
    BadTopicError,
    DuplicateGroupError,
    DuplicateTopicError,
    MessageBroker,
    MessageBrokerError,
    SeqOrderError,
    UnknownGroupError,
    UnknownTopicError,
    message_broker_audit_event,
)


def _pd(ch: str = "a") -> str:
    return "sha256:" + ch * 64


@pytest.fixture()
def broker() -> MessageBroker:
    return MessageBroker()


@pytest.fixture()
def loaded() -> MessageBroker:
    b = MessageBroker()
    b.declare_topic("t1", 2, 1)
    b.create_group("g1", 2)
    return b


def test_version_pins():
    assert message_broker.MESSAGE_BROKER_VERSION == "message-broker.v1"
    assert message_broker.MESSAGE_BROKER_SCHEMA == "northstar.message-broker.v1"


def test_stdlib_only_ast():
    tree = ast.parse(open(message_broker.__file__).read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "__future__",
        "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_declare_topic_roundtrip(broker):
    trec = broker.declare_topic("orders", 3, 1)
    assert trec.verify()
    assert broker.topic("orders").partitions == 3
    assert broker.topic_ids() == ("orders",)


def test_declare_topic_duplicate(broker):
    broker.declare_topic("orders", 1, 1)
    with pytest.raises(DuplicateTopicError):
        broker.declare_topic("orders", 1, 2)


@pytest.mark.parametrize(
    "topic_id,partitions",
    [
        ("", 1),
        ("   ", 2),
        ("t", 0),
        ("t", 65),
        ("t", True),
        ("t", "2"),
    ],
)
def test_declare_topic_bad_inputs(broker, topic_id, partitions):
    with pytest.raises(MessageBrokerError):
        broker.declare_topic(topic_id, partitions, 1)


def test_publish_roundtrip_and_offsets(loaded):
    m1 = loaded.publish("t1", "k1", _pd(), 3)
    m2 = loaded.publish("t1", "k2", _pd("b"), 4)
    assert m1.verify() and m2.verify()
    assert m1.partition in (0, 1) and m2.partition in (0, 1)
    # Same partition: offsets strictly increase.
    same = [m for m in (m1, m2) if m.partition == m1.partition]
    if len(same) == 2:
        assert same[1].offset == same[0].offset + 1
    assert loaded.message(m1.message_id).payload_digest == _pd()


def test_publish_explicit_partition(loaded):
    m = loaded.publish("t1", "k", _pd(), 3, partition=1)
    assert m.partition == 1
    assert m.offset == 0


def test_publish_deterministic_partition(loaded):
    # Same key -> same partition (deterministic), across instances.
    m_a = loaded.publish("t1", "stable-key", _pd(), 3)
    other = MessageBroker()
    other.declare_topic("t1", 2, 1)
    m_b = other.publish("t1", "stable-key", _pd(), 2)
    assert m_a.partition == m_b.partition


@pytest.mark.parametrize("bad_digest", ["", "abc", "sha256:xyz", "sha256:" + "g" * 64])
def test_publish_bad_digest(loaded, bad_digest):
    with pytest.raises(BadMessageError):
        loaded.publish("t1", "k", bad_digest, 3)


def test_publish_bad_inputs(loaded):
    s = [3]
    def nxt():
        s[0] += 1
        return s[0]
    with pytest.raises(UnknownTopicError):
        loaded.publish("nope", "k", _pd(), nxt())
    with pytest.raises(MessageBrokerError):
        loaded.publish("t1", "", _pd(), nxt())
    with pytest.raises(BadMessageError):
        loaded.publish("t1", "k", _pd(), nxt(), partition=7)


def test_create_group_roundtrip_and_duplicate(broker):
    grec = broker.create_group("g1", 1)
    assert grec.verify()
    assert broker.group("g1").group_id == "g1"
    assert broker.group_ids() == ("g1",)
    with pytest.raises(DuplicateGroupError):
        broker.create_group("g1", 2)
    with pytest.raises(UnknownGroupError):
        broker.group("nope")
    with pytest.raises(BadGroupError):
        broker.create_group("  ", 3)


def test_consume_in_order_and_limit(loaded):
    for i in range(5):
        loaded.publish("t1", f"k{i}", _pd(), 3 + i)
    page = loaded.consume("g1", "t1", 10, max_messages=3)
    assert page.verify()
    assert len(page.deliveries) == 3
    # Within a partition, offsets ascend.
    by_part: dict = {}
    for d in page.deliveries:
        assert d.verify()
        by_part.setdefault(d.partition, []).append(d.offset)
    for offs in by_part.values():
        assert offs == sorted(offs)


def test_consume_full_then_empty(loaded):
    loaded.publish("t1", "k", _pd(), 3)
    page = loaded.consume("g1", "t1", 4)
    assert len(page.deliveries) == 1
    # No ack yet: consume again redelivers (at-least-once booking).
    page2 = loaded.consume("g1", "t1", 5)
    assert len(page2.deliveries) == 1
    loaded.ack("g1", "t1", 6)
    page3 = loaded.consume("g1", "t1", 7)
    assert len(page3.deliveries) == 0


def test_ack_commits_and_advances(loaded):
    loaded.publish("t1", "k1", _pd(), 3)
    loaded.publish("t1", "k2", _pd(), 4)
    assert loaded.pending("g1", "t1") == 2
    loaded.consume("g1", "t1", 5)  # book the deliveries before acking
    commit = loaded.ack("g1", "t1", 6)
    assert commit.verify()
    assert loaded.pending("g1", "t1") == 0
    assert all(off > 0 for _, off in commit.committed)


def test_ack_explicit_point(loaded):
    loaded.publish("t1", "k", _pd(), 3, partition=0)
    commit = loaded.ack("g1", "t1", 4, partition=0, offset=1)
    assert commit.committed == ((0, 1),)
    assert loaded.committed_offset("g1", "t1", 0) == 1


def test_ack_bad_inputs(loaded):
    s = [2]
    def nxt():
        s[0] += 1
        return s[0]
    with pytest.raises(BadAckError):
        loaded.ack("g1", "t1", nxt())  # nothing delivered yet
    with pytest.raises(UnknownGroupError):
        loaded.ack("nope", "t1", nxt())
    with pytest.raises(UnknownTopicError):
        loaded.ack("g1", "nope", nxt())
    with pytest.raises(BadAckError):
        loaded.ack("g1", "t1", nxt(), partition=0)  # offset missing
    with pytest.raises(BadAckError):
        loaded.ack("g1", "t1", nxt(), partition=9, offset=1)
    # Rewind refused.
    loaded.publish("t1", "k", _pd(), nxt(), partition=0)
    loaded.ack("g1", "t1", nxt(), partition=0, offset=1)
    with pytest.raises(BadAckError):
        loaded.ack("g1", "t1", nxt(), partition=0, offset=0)


def test_seq_rewind_and_bool(broker):
    broker.declare_topic("t", 1, 1)
    with pytest.raises(SeqOrderError):
        broker.declare_topic("t2", 1, 1)
    with pytest.raises(SeqOrderError):
        broker.create_group("g", True)
    with pytest.raises(SeqOrderError):
        broker.declare_topic("t2", 1, -1)


def test_failed_mutation_consumes_seq(broker):
    broker.declare_topic("t", 1, 1)
    with pytest.raises(DuplicateTopicError):
        broker.declare_topic("t", 1, 2)  # seq 2 burned
    with pytest.raises(SeqOrderError):
        broker.create_group("g", 2)


def test_audit_shapes_and_leak_ban(loaded):
    loaded.publish("t1", "secret-key", _pd(), 3)
    kinds = [e["kind"] for e in loaded.audit_log()]
    assert "message-broker.topic-declared" in kinds
    assert "message-broker.published" in kinds
    for e in loaded.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert "prev_digest" in e
        assert "secret-key" not in str(e["detail"])
        assert "key" not in e["detail"]
    # Banned keys refused.
    with pytest.raises(MessageBrokerError):
        message_broker_audit_event("message-broker.published", {"key": "k"}, 9)
    with pytest.raises(AuditKindError):
        message_broker_audit_event("bogus.kind", {}, 9)


def test_views_and_stats(loaded):
    loaded.publish("t1", "k", _pd(), 3)
    assert loaded.stats() == {"topics": 1, "groups": 1, "messages": 1}
    d = loaded.as_dict()
    assert d["version"] == "message-broker.v1"
    assert d["topics"] == ["t1"]


def test_main_subprocess():
    r = subprocess.run(
        [sys.executable, message_broker.__file__],
        capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, r.stderr
    assert "message-broker OK" in r.stdout
