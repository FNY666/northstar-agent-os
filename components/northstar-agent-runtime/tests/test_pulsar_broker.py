"""Tests for pulsar_broker.py (15 tests)."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pulsar_broker import (
    AUDIT_SCHEMA,
    PULSAR_BROKER_SCHEMA,
    PULSAR_BROKER_VERSION,
    BadMessageError,
    BadPositionError,
    BadSubscriptionError,
    BadTopicError,
    DeletedTopicError,
    DuplicateSubscriptionError,
    DuplicateTopicError,
    PulsarBroker,
    PulsarBrokerError,
    RemovedSubscriptionError,
    SeqOrderError,
    UnknownMessageError,
    UnknownSubscriptionError,
    UnknownTopicError,
    pulsar_broker_audit_event,
)

_DIGEST = "sha256:" + "ab" * 32


def fresh() -> PulsarBroker:
    return PulsarBroker()


def make_topic(broker: PulsarBroker, tid: str = "t1", seq: int = 1, **kw):
    kw.setdefault("name", f"persistent://public/default/{tid}-topic")
    return broker.topic(tid, kw["name"], seq, **{k: v for k, v in kw.items() if k != "name"})


# 1 ---------------------------------------------------------------------


def test_version_schema_pins():
    assert PULSAR_BROKER_VERSION == "pulsar-broker.v1"
    assert PULSAR_BROKER_SCHEMA == "northstar.pulsar-broker.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


# 2 ---------------------------------------------------------------------


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "pulsar_broker.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "hashlib", "re", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3 ---------------------------------------------------------------------


def test_topic_roundtrip_and_name_normalization():
    broker = fresh()
    t = broker.topic("t1", "persistent://tenant1/ns1/orders", 1, partitions=4)
    assert t.topic_id == "t1"
    assert (t.persistence, t.tenant, t.namespace, t.name) == (
        "persistent", "tenant1", "ns1", "orders")
    assert t.partitions == 4 and t.seq == 1 and not t.deleted
    assert t.verify()
    # shorthand + bare name defaults
    t2 = broker.topic("t2", "tenant2/ns2/events", 2)
    assert (t2.tenant, t2.namespace, t2.name) == ("tenant2", "ns2", "events")
    t3 = broker.topic("t3", "bare-topic", 3)
    assert (t3.tenant, t3.namespace) == ("public", "default")
    assert broker.topic_ids() == ("t1", "t2", "t3")
    # frozen
    with pytest.raises(Exception):
        t.partitions = 8  # type: ignore[misc]


# 4 ---------------------------------------------------------------------


def test_topic_bad_inputs_and_duplicates():
    broker = fresh()
    make_topic(broker)
    with pytest.raises(DuplicateTopicError):
        broker.topic("t1", "persistent://public/default/other", 2)
    bad_names = ["", "   ", "bad://x/y", "a/b/c/d", "up//name", "TENANT/ns/x!"]
    seq = 10
    for i, name in enumerate(bad_names):
        with pytest.raises(BadTopicError):
            broker.topic(f"bx{i}", name, seq)  # failed mutation consumes seq
        seq += 1
    with pytest.raises(BadTopicError):
        broker.topic("p0", "persistent://public/default/x", 100, partitions=0)
    with pytest.raises(BadTopicError):
        broker.topic("p1", "persistent://public/default/x", 101, partitions=True)
    with pytest.raises(BadTopicError):
        broker.topic("p2", "persistent://public/default/x", 102, persistence="ephemeral")
    # audit recorded the rejections
    kinds = [e["kind"] for e in broker.audit_log()]
    assert "pulsar.rejected" in kinds


# 5 ---------------------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    broker = fresh()
    make_topic(broker, seq=1)
    with pytest.raises(SeqOrderError):
        broker.topic("t9", "persistent://public/default/x", 1)  # rewind
    with pytest.raises(SeqOrderError):
        broker.topic("t9", "persistent://public/default/x", True)  # bool
    # failed mutation consumed seq=2 -> next valid is 3
    with pytest.raises(DuplicateTopicError):
        broker.topic("t1", "persistent://public/default/x", 2)
    ok = broker.topic("t9", "persistent://public/default/x", 3)
    assert ok.topic_id == "t9"


# 6 ---------------------------------------------------------------------


def test_publish_roundtrip_partition_assignment():
    broker = fresh()
    make_topic(broker, partitions=2)
    m1 = broker.publish("t1", 2, _DIGEST)
    m2 = broker.publish("t1", 3, _DIGEST)
    m3 = broker.publish("t1", 4, _DIGEST)
    assert (m1.msg_id, m2.msg_id, m3.msg_id) == ("msg-1", "msg-2", "msg-3")
    # deterministic partition assignment: msg_index % partitions
    assert (m1.partition, m2.partition, m3.partition) == (0, 1, 0)
    assert (m1.msg_index, m2.msg_index, m3.msg_index) == (0, 1, 2)
    assert all(m.verify() for m in (m1, m2, m3))
    assert broker.message_record("msg-2").payload_digest == _DIGEST
    with pytest.raises(BadMessageError):
        broker.publish("t1", 5, "not-a-digest")
    with pytest.raises(UnknownTopicError):
        broker.publish("nope", 6, _DIGEST)


# 7 ---------------------------------------------------------------------


def test_subscription_roundtrip_pinned_types():
    broker = fresh()
    make_topic(broker)
    s = broker.subscription("t1", "s1", "shared", 2)
    assert (s.subscription_id, s.sub_type, s.initial_position) == (
        "s1", "shared", "earliest")
    assert s.verify()
    with pytest.raises(DuplicateSubscriptionError):
        broker.subscription("t1", "s1", "shared", 3)
    with pytest.raises(BadSubscriptionError):
        broker.subscription("t1", "s2", "broadcast", 4)
    with pytest.raises(BadSubscriptionError):
        broker.subscription("t1", "s2", "shared", 5, initial_position="middle")
    with pytest.raises(UnknownTopicError):
        broker.subscription("nope", "s3", "shared", 6)
    assert broker.subscription_ids() == ("s1",)
    assert broker.subscription_ids("t1") == ("s1",)
    assert broker.subscription_record("s1").sub_type == "shared"


# 8 ---------------------------------------------------------------------


def test_cursor_initial_view_is_pure_read():
    broker = fresh()
    make_topic(broker, partitions=2)
    broker.publish("t1", 2, _DIGEST)
    broker.publish("t1", 3, _DIGEST)
    broker.subscription("t1", "se", "exclusive", 4, initial_position="earliest")
    broker.subscription("t1", "sl", "exclusive", 5, initial_position="latest")
    ve = broker.cursor("se", 6)
    vl = broker.cursor("sl", 6)
    assert ve.verify() and vl.verify()
    # earliest sees both messages; latest sees none
    assert sum(p.backlog for p in ve.partitions) == 2
    assert sum(p.backlog for p in vl.partitions) == 0
    for p in ve.partitions:
        assert p.published == 1 and p.cursor == 0
    # seq validated, not consumed: same seq can be reused
    broker.cursor("se", 6)
    # per-partition fields are sane
    parts = {p.partition: p for p in ve.partitions}
    assert set(parts) == {0, 1}


# 9 ---------------------------------------------------------------------


def test_acknowledge_advances_cursor_cumulatively():
    broker = fresh()
    make_topic(broker, partitions=1)
    m1 = broker.publish("t1", 2, _DIGEST)
    m2 = broker.publish("t1", 3, _DIGEST)
    m3 = broker.publish("t1", 4, _DIGEST)
    broker.subscription("t1", "s1", "shared", 5)
    ack = broker.acknowledge("s1", 6, m2.msg_id)  # cumulative: skips msg-1 too
    assert ack.verify()
    view = broker.cursor("s1", 7)
    (p,) = view.partitions
    assert p.cursor == 2 and p.backlog == 1  # only msg-3 remains
    # acking an already-passed message refuses
    with pytest.raises(BadPositionError):
        broker.acknowledge("s1", 8, m1.msg_id)
    # acking an unknown message refuses
    with pytest.raises(UnknownMessageError):
        broker.acknowledge("s1", 9, "msg-999")
    # acking a message from another topic refuses
    broker.topic("t2", "persistent://public/default/other", 10)
    mx = broker.publish("t2", 11, _DIGEST)
    with pytest.raises(BadPositionError):
        broker.acknowledge("s1", 12, mx.msg_id)


# 10 --------------------------------------------------------------------


def test_seek_rewinds_cursor():
    broker = fresh()
    make_topic(broker, partitions=1)
    m1 = broker.publish("t1", 2, _DIGEST)
    broker.publish("t1", 3, _DIGEST)
    broker.subscription("t1", "s1", "shared", 4)
    broker.acknowledge("s1", 5, m1.msg_id)  # cursor -> 1, backlog 1
    seek = broker.seek("s1", 6, m1.msg_id)  # rewind to index 0
    assert seek.verify()
    view = broker.cursor("s1", 7)
    (p,) = view.partitions
    assert p.cursor == 0 and p.backlog == 2
    with pytest.raises(UnknownMessageError):
        broker.seek("s1", 8, "msg-999")


# 11 --------------------------------------------------------------------


def test_unsubscribe_terminality():
    broker = fresh()
    make_topic(broker)
    broker.subscription("t1", "s1", "shared", 2)
    broker.unsubscribe("s1", 3, reason="done")
    assert broker.subscription_ids() == ()
    with pytest.raises(RemovedSubscriptionError):
        broker.cursor("s1", 4)
    with pytest.raises(RemovedSubscriptionError):
        broker.unsubscribe("s1", 5)
    with pytest.raises(UnknownSubscriptionError):
        broker.unsubscribe("nope", 6)


# 12 --------------------------------------------------------------------


def test_delete_topic_refuses_active_subscriptions():
    broker = fresh()
    make_topic(broker)
    broker.subscription("t1", "s1", "shared", 2)
    with pytest.raises(PulsarBrokerError):
        broker.delete_topic("t1", 3)
    assert broker.topic_ids() == ("t1",)  # still there
    broker.unsubscribe("s1", 4)
    broker.delete_topic("t1", 5, reason="retire")
    assert broker.topic_ids() == ()
    with pytest.raises(DeletedTopicError):
        broker.publish("t1", 6, _DIGEST)
    with pytest.raises(DeletedTopicError):
        broker.subscription("t1", "s9", "shared", 7)


# 13 --------------------------------------------------------------------


def test_audit_shapes_banned_keys_and_bad_kind():
    broker = fresh()
    make_topic(broker)
    broker.publish("t1", 2, _DIGEST)
    broker.subscription("t1", "s1", "shared", 3)
    kinds = [e["kind"] for e in broker.audit_log()]
    assert kinds[:3] == [
        "pulsar.topic-defined", "pulsar.message-published", "pulsar.subscribed"]
    for event in broker.audit_log():
        assert event["schema"] == AUDIT_SCHEMA
        assert event["module"] == PULSAR_BROKER_VERSION
    # banned payload keys refused
    with pytest.raises(PulsarBrokerError):
        pulsar_broker_audit_event(
            "pulsar.message-published", {"payload": b"raw"}, 99)
    with pytest.raises(PulsarBrokerError):
        pulsar_broker_audit_event("nope", {}, 99)


# 14 --------------------------------------------------------------------


def test_stats_and_digest_determinism():
    b1, b2 = fresh(), fresh()
    for b in (b1, b2):
        b.topic("t1", "persistent://public/default/x", 1, partitions=2)
        b.publish("t1", 2, _DIGEST)
        b.subscription("t1", "s1", "shared", 3)
    assert b1.stats()["digest"] == b2.stats()["digest"]
    stats = b1.stats()
    assert stats["topics"] == 1 and stats["messages"] == 1
    assert stats["subscriptions"] == 1
    assert stats["schema"] == PULSAR_BROKER_SCHEMA
    # thread-safety smoke: RLock present
    import threading
    assert isinstance(b1._lock, type(threading.RLock()))


# 15 ---------------------------------------------------------------------


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, os.path.join(
            os.path.dirname(__file__), "..", "pulsar_broker.py")],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "pulsar-broker OK" in proc.stdout
