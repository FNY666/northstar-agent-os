"""Tests for the STOMP broker ledger."""

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import stomp_broker
from stomp_broker import (
    STOMPBroker,
    STOMP_BROKER_VERSION,
    STOMP_BROKER_SCHEMA,
    AckRecord,
    BadAckModeError,
    BadBodyDigestError,
    BadConnectionError,
    BadDestinationError,
    BadHeaderError,
    DisconnectedError,
    DuplicateConnectionError,
    DuplicateSubscriptionError,
    DuplicateTransactionError,
    SeqOrderError,
    UnknownConnectionError,
    UnknownMessageError,
    UnknownSubscriptionError,
    UnknownTransactionError,
    stomp_broker_audit_event,
)

GOOD_DIGEST = "sha256:" + hashlib.sha256(b"payload").hexdigest()


def _broker():
    b = STOMPBroker()
    b.connect("c1", 1)
    return b


def test_version_pins():
    assert STOMP_BROKER_VERSION == "stomp-broker.v1"
    assert STOMP_BROKER_SCHEMA == "northstar.stomp-broker.v1"


def test_stdlib_only():
    src = Path(stomp_broker.__file__).read_text()
    tree = ast.parse(src)
    allowed = {"hashlib", "threading", "dataclasses", "typing",
               "json", "canonical_json", "__future__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_connect_roundtrip_and_verify():
    b = STOMPBroker()
    rec = b.connect("c1", 1, login="guest", heartbeat=(100, 200))
    assert rec.connection_id == "c1"
    assert rec.login == "guest"
    assert rec.verify()
    assert b.connection_record("c1") is rec
    # duplicate refused, seq consumed
    with pytest.raises(DuplicateConnectionError):
        b.connect("c1", 2)
    with pytest.raises(SeqOrderError):
        b.connect("c2", 2)  # seq 2 already consumed


def test_connect_bad_inputs():
    b = STOMPBroker()
    with pytest.raises(BadConnectionError):
        b.connect("c1", 1, heartbeat=(1,))  # bad shape
    with pytest.raises(BadConnectionError):
        b.connect("c2", 2, heartbeat=(-1, 0))  # negative
    with pytest.raises(UnknownConnectionError):
        b.connection_record("nope")


def test_disconnect_terminal():
    b = _broker()
    rec = b.disconnect("c1", 2)
    assert rec.verify()
    with pytest.raises(DisconnectedError):
        b.send("c1", "/queue/a", GOOD_DIGEST, 3)
    with pytest.raises(DisconnectedError):
        b.subscribe("c1", "s1", "/queue/a", 4)
    assert b.live_connection_ids() == []


def test_send_and_destination_validation():
    b = _broker()
    msg = b.send("c1", "/queue/orders", GOOD_DIGEST, 2)
    assert msg.message_id == "msg-1"
    assert msg.verify()
    assert b.message_record("msg-1") is msg
    with pytest.raises(BadDestinationError):
        b.send("c1", "orders", GOOD_DIGEST, 3)  # no /queue/ or /topic/
    with pytest.raises(BadBodyDigestError):
        b.send("c1", "/queue/a", "not-a-digest", 4)
    with pytest.raises(UnknownMessageError):
        b.message_record("msg-999")


def test_send_headers_and_receipt():
    b = _broker()
    msg = b.send(
        "c1", "/topic/news", GOOD_DIGEST, 2,
        headers=(("content-type", "application/json"),),
        receipt="r-7",
    )
    assert msg.headers == (("content-type", "application/json"),)
    rec = b.receipt_record("r-7")
    assert rec.for_frame == "SEND"
    assert rec.verify()
    with pytest.raises(BadHeaderError):
        b.send("c1", "/queue/a", GOOD_DIGEST, 3,
               headers=(("message-id", "x"),))  # reserved


def test_subscribe_ack_modes():
    b = _broker()
    s = b.subscribe("c1", "s1", "/queue/a", 2, ack="client-individual")
    assert s.ack_mode == "client-individual"
    assert s.verify()
    assert b.subscription_record("c1", "s1") is s
    with pytest.raises(BadAckModeError):
        b.subscribe("c1", "s2", "/queue/a", 3, ack="manual")
    with pytest.raises(DuplicateSubscriptionError):
        b.subscribe("c1", "s1", "/queue/b", 4)
    with pytest.raises(UnknownSubscriptionError):
        b.subscription_record("c1", "nope")
    un = b.unsubscribe("c1", "s1", 5)
    assert un.verify()
    with pytest.raises(UnknownSubscriptionError):
        b.unsubscribe("c1", "s1", 6)


def test_deliver_ack_nack_cycle():
    b = _broker()
    b.subscribe("c1", "s1", "/queue/a", 2, ack="client")
    b.send("c1", "/queue/a", GOOD_DIGEST, 3)
    b.send("c1", "/queue/a", GOOD_DIGEST, 4)
    page = b.deliver("c1", 5)
    assert len(page.messages) == 2
    assert page.verify()
    mid = page.messages[0].message_id
    ack = b.ack("c1", mid, 6)
    assert isinstance(ack, AckRecord) and ack.verdict == "acked"
    assert ack.verify()
    nack = b.nack("c1", page.messages[1].message_id, 7)
    assert nack.verdict == "nacked"
    # second deliver finds nothing unsettled
    page2 = b.deliver("c1", 8)
    assert len(page2.messages) == 0
    with pytest.raises(UnknownMessageError):
        b.ack("c1", "msg-999", 9)


def test_transaction_commit_and_abort():
    b = _broker()
    b.subscribe("c1", "s1", "/queue/a", 2)
    t = b.begin("c1", "tx1", 3)
    assert t.state == "booked"
    b.send("c1", "/queue/a", GOOD_DIGEST, 4, transaction="tx1")
    # staged: not deliverable yet
    assert len(b.deliver("c1", 5).messages) == 0
    c = b.commit("c1", "tx1", 6)
    assert c.state == "committed"
    assert len(b.deliver("c1", 7).messages) == 1
    b.begin("c1", "tx2", 8)
    b.send("c1", "/queue/a", GOOD_DIGEST, 9, transaction="tx2")
    a = b.abort("c1", "tx2", 10)
    assert a.state == "aborted"
    with pytest.raises(DuplicateTransactionError):
        b.begin("c1", "tx3", 11)
        b.begin("c1", "tx3", 12)
    with pytest.raises(UnknownTransactionError):
        b.commit("c1", "nope", 13)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    b = STOMPBroker()
    b.connect("c1", 5)
    with pytest.raises(SeqOrderError):
        b.connect("c2", 5)  # not strictly increasing
    with pytest.raises(SeqOrderError):
        b.connect("c3", 3)  # rewind
    # failed mutation consumed seq 6
    with pytest.raises(DuplicateConnectionError):
        b.connect("c1", 6)
    with pytest.raises(SeqOrderError):
        b.connect("c2", 6)


def test_audit_shapes_and_banned_keys():
    ev = stomp_broker_audit_event("stomp.sent",
                                  {"connection_id": "c1", "message_id": "msg-1"}, 3)
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == "stomp-broker.v1"
    b = _broker()
    b.send("c1", "/queue/a", GOOD_DIGEST, 2)
    kinds = {e["kind"] for e in b.audit_log()}
    assert "stomp.connected" in kinds and "stomp.sent" in kinds
    with pytest.raises(Exception):
        stomp_broker_audit_event("stomp.sent", {"body": b"x"}, 9)  # banned
    with pytest.raises(Exception):
        stomp_broker_audit_event("bogus.kind", {}, 9)


def test_views_and_stats():
    b = _broker()
    b.subscribe("c1", "s1", "/topic/t", 2)
    b.send("c1", "/topic/t", GOOD_DIGEST, 3)
    stats = b.stats()
    assert stats["connections"] == 1
    assert stats["messages"] == 1
    assert stats["subscriptions"] == 1
    snap = b.as_dict()
    assert snap["version"] == "stomp-broker.v1"
    assert snap["stats"]["messages"] == 1


def test_disconnect_cancels_subscriptions():
    b = _broker()
    b.subscribe("c1", "s1", "/queue/a", 2)
    b.disconnect("c1", 3)
    with pytest.raises(UnknownSubscriptionError):
        b.subscription_record("c1", "s1")


def test_main_self_check():
    r = subprocess.run([sys.executable, stomp_broker.__file__],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "stomp-broker OK" in r.stdout
