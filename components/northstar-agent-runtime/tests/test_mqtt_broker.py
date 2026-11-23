"""Tests for mqtt_broker: 15 cases."""

import ast
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mqtt_broker
from mqtt_broker import (
    MQTT_BROKER_VERSION,
    MQTT_BROKER_SCHEMA,
    AUDIT_SCHEMA,
    MQTTBroker,
    MQTTBrokerError,
    BadDigestError,
    BadFilterError,
    BadQoSError,
    BadTopicError,
    DuplicateSubscriptionError,
    SeqOrderError,
    UnknownRetainedError,
    UnknownSubscriptionError,
    mqtt_broker_audit_event,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def fresh():
    return MQTTBroker()


# 1 ---------------------------------------------------------------------


def test_version_schema_pins():
    assert MQTT_BROKER_VERSION == "mqtt-broker.v1"
    assert MQTT_BROKER_SCHEMA == "northstar.mqtt-broker.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    broker = fresh()
    sub = broker.subscribe("c1", "a/b", 1)
    assert sub.verify()
    pub = broker.publish("a/b", DIGEST_A, 2)
    assert pub.verify()
    ret = broker.retain("a/b", 3, DIGEST_A)
    assert ret.verify()
    unsub = broker.unsubscribe("c1", "a/b", 4)
    assert unsub.verify()


# 2 ---------------------------------------------------------------------


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "mqtt_broker.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "hashlib", "re", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__", "ast",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3 ---------------------------------------------------------------------


def test_subscribe_roundtrip_and_duplicate():
    broker = fresh()
    sub = broker.subscribe("c1", "home/+/temp", 1, qos=2)
    assert sub.client_id == "c1"
    assert sub.topic_filter == "home/+/temp"
    assert sub.qos == 2
    assert sub.seq == 1
    # frozen
    try:
        sub.qos = 0  # type: ignore[misc]
    except Exception as exc:
        assert type(exc).__name__ == "FrozenInstanceError"
    else:
        raise AssertionError("records must be frozen")
    # digest deterministic across instances
    other = fresh()
    sub2 = other.subscribe("c1", "home/+/temp", 1, qos=2)
    assert sub.digest == sub2.digest
    # duplicate refused
    try:
        broker.subscribe("c1", "home/+/temp", 2)
    except DuplicateSubscriptionError:
        pass
    else:
        raise AssertionError("duplicate subscription must raise")
    # views
    assert broker.subscription("c1", "home/+/temp").digest == sub.digest
    assert ("c1", "home/+/temp") in broker.subscription_ids()
    assert "c1" in broker.client_ids()


# 4 ---------------------------------------------------------------------


def test_bad_filters():
    broker = fresh()
    bad = [
        "", "   ", "a//b", "/a", "a/", "sport/#/rank", "sport/tennis#",
        "sport/te+nis", "a b/c", "#/a",
    ]
    seq = 1
    for filt in bad:
        try:
            broker.subscribe("c1", filt, seq)
        except (BadFilterError, MQTTBrokerError):
            pass
        else:
            raise AssertionError(f"bad filter {filt!r} must raise")
        seq += 1
    # good ones
    for filt in ["#", "a/#", "a/+/c", "+/b", "a/b/c"]:
        broker.subscribe("c1", filt, seq)
        seq += 1


# 5 ---------------------------------------------------------------------


def test_unsubscribe_roundtrip_and_unknown():
    broker = fresh()
    broker.subscribe("c1", "a/b", 1)
    unsub = broker.unsubscribe("c1", "a/b", 2)
    assert unsub.verify()
    assert broker.subscription_ids() == ()
    try:
        broker.unsubscribe("c1", "a/b", 3)
    except UnknownSubscriptionError:
        pass
    else:
        raise AssertionError("unknown subscription must raise")
    try:
        broker.subscription("c1", "a/b")
    except UnknownSubscriptionError:
        pass
    else:
        raise AssertionError("retired subscription must raise")


# 6 ---------------------------------------------------------------------


def test_publish_fanout_and_qos_min():
    broker = fresh()
    broker.subscribe("fast", "a/b", 1, qos=0)
    broker.subscribe("slow", "a/b", 2, qos=2)
    pub = broker.publish("a/b", DIGEST_A, 3, qos=1)
    assert pub.publish_id == "pub-1"
    assert pub.verify()
    fast = broker.deliveries_for("fast")
    slow = broker.deliveries_for("slow")
    assert len(fast) == 1 and len(slow) == 1
    # qos = min(publish, subscription)
    assert fast[0].qos == 0
    assert slow[0].qos == 1
    assert fast[0].verify() and slow[0].verify()
    assert not fast[0].retained
    # publish to a topic with no subscribers still books
    pub2 = broker.publish("x/y", DIGEST_B, 4)
    assert pub2.publish_id == "pub-2"
    assert broker.deliveries_for("fast") == fast  # unchanged


# 7 ---------------------------------------------------------------------


def test_wildcard_matching():
    broker = fresh()
    broker.subscribe("plus", "sport/+/player", 1)
    broker.subscribe("hash", "sport/#", 2)
    broker.publish("sport/tennis/player", DIGEST_A, 3)
    broker.publish("sport/tennis/player/rank", DIGEST_B, 4)
    plus = broker.deliveries_for("plus")
    hash_ = broker.deliveries_for("hash")
    # '+' matches exactly one level
    assert [d.topic for d in plus] == ["sport/tennis/player"]
    # '#' matches the rest of the tree
    assert sorted(d.topic for d in hash_) == [
        "sport/tennis/player", "sport/tennis/player/rank",
    ]


# 8 ---------------------------------------------------------------------


def test_bad_qos_and_digest():
    broker = fresh()
    for bad_qos in (-1, 3, True, "1", 1.0, None):
        try:
            broker.subscribe("c1", "a/b", 1, qos=bad_qos)
        except (BadQoSError, MQTTBrokerError):
            pass
        else:
            raise AssertionError(f"bad qos {bad_qos!r} must raise")
        try:
            broker.publish("a/b", DIGEST_A, 2, qos=bad_qos)
        except (BadQoSError, MQTTBrokerError):
            pass
        else:
            raise AssertionError(f"bad qos {bad_qos!r} must raise")
    for bad_digest in ("", "abc", "md5:" + "a" * 32, "sha256:" + "z" * 64,
                       "sha256:" + "a" * 63, None, 123):
        try:
            broker.publish("a/b", bad_digest, 10)
        except (BadDigestError, MQTTBrokerError):
            pass
        else:
            raise AssertionError(f"bad digest {bad_digest!r} must raise")


# 9 ---------------------------------------------------------------------


def test_bad_publish_topics():
    broker = fresh()
    for bad in ["", "a//b", "a/+", "a/#", "#", "+", "a b", "a/" * 600]:
        try:
            broker.publish(bad, DIGEST_A, 1)
        except (BadTopicError, MQTTBrokerError):
            pass
        else:
            raise AssertionError(f"bad topic {bad!r} must raise")


# 10 --------------------------------------------------------------------


def test_retain_set_catchup_and_clear():
    broker = fresh()
    ret = broker.retain("a/b", 1, DIGEST_A)
    assert ret.verify() and not ret.cleared
    # new subscriber catches up flagged retained
    broker.subscribe("c1", "a/#", 2)
    caught = broker.deliveries_for("c1")
    assert len(caught) == 1
    assert caught[0].retained and caught[0].topic == "a/b"
    assert caught[0].verify()
    # overwrite retained
    broker.retain("a/b", 3, DIGEST_B)
    view = broker.retained("a/b")
    assert view.payload_digest == DIGEST_B and view.verify()
    # clear
    cleared = broker.retain("a/b", 4)
    assert cleared.verify() and cleared.cleared
    try:
        broker.retained("a/b")
    except UnknownRetainedError:
        pass
    else:
        raise AssertionError("cleared retained must raise")
    # clearing unknown topic refuses
    try:
        broker.retain("nope/x", 5)
    except UnknownRetainedError:
        pass
    else:
        raise AssertionError("clearing unknown retained must raise")


# 11 --------------------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    broker = fresh()
    broker.subscribe("c1", "a/b", 5)
    for bad_seq in (5, 3, -1, True, "6", 5.0):
        try:
            broker.subscribe("c2", "x/y", bad_seq)
        except SeqOrderError:
            pass
        else:
            raise AssertionError(f"bad seq {bad_seq!r} must raise")
    # failed mutation consumed its seq: next must exceed the failed one
    try:
        broker.subscribe("c1", "a/b", 6)  # duplicate -> refused
    except DuplicateSubscriptionError:
        pass
    else:
        raise AssertionError("duplicate must raise")
    try:
        broker.subscribe("c2", "x/y", 6)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("consumed seq must still be claimed")
    ok = broker.subscribe("c2", "x/y", 7)
    assert ok.verify()


# 12 --------------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    broker = fresh()
    broker.subscribe("c1", "a/b", 1)
    broker.publish("a/b", DIGEST_A, 2)
    broker.retain("a/b", 3, DIGEST_A)
    broker.retain("a/b", 4)
    broker.unsubscribe("c1", "a/b", 5)
    try:
        broker.subscribe("c1", "a/b", 6)
        broker.subscribe("c1", "a/b", 7)  # duplicate -> rejected
    except DuplicateSubscriptionError:
        pass
    kinds = [e["kind"] for e in broker.audit_log()]
    assert kinds == [
        "mqtt.subscribed", "mqtt.published", "mqtt.retained-set",
        "mqtt.retained-cleared", "mqtt.unsubscribed",
        "mqtt.subscribed", "mqtt.rejected",
    ]
    for event in broker.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        assert "payload" not in event["detail"]
    # helper validates kinds and bans payload keys
    try:
        mqtt_broker_audit_event("mqtt.bogus", {}, 1)
    except MQTTBrokerError:
        pass
    else:
        raise AssertionError("bad audit kind must raise")
    try:
        mqtt_broker_audit_event("mqtt.published", {"payload": b"x"}, 1)
    except MQTTBrokerError:
        pass
    else:
        raise AssertionError("banned audit key must raise")


# 13 --------------------------------------------------------------------


def test_views_and_stats():
    broker = fresh()
    assert broker.stats(1) == {
        "subscriptions": 0, "clients": 0, "retained_topics": 0,
        "publishes": 0, "deliveries": 0,
    }
    broker.subscribe("c1", "a/b", 2)
    broker.subscribe("c1", "a/#", 3)
    broker.subscribe("c2", "x/y", 4)
    broker.retain("r/t", 5, DIGEST_A)
    broker.publish("a/b", DIGEST_A, 6)
    stats = broker.stats(7)
    assert stats["subscriptions"] == 3
    assert stats["clients"] == 2
    assert stats["retained_topics"] == 1
    assert stats["publishes"] == 1
    # c1 matched a/b via both filters -> 2 deliveries
    assert stats["deliveries"] == 2
    # stats is a pure read: seq not consumed
    broker.subscribe("c3", "q/w", 7)
    assert broker.subscription("c3", "q/w").verify()


# 14 --------------------------------------------------------------------


def test_no_subscriber_publish_and_retained_isolation():
    broker = fresh()
    # publish with no subscribers: booked, zero deliveries
    pub = broker.publish("lonely/topic", DIGEST_A, 1)
    assert pub.verify()
    assert broker.stats(2)["deliveries"] == 0
    # retained on one topic does not leak to non-matching subscriber
    broker.retain("a/b", 3, DIGEST_A)
    broker.subscribe("c1", "x/#", 4)
    assert broker.deliveries_for("c1") == ()
    broker.subscribe("c2", "a/+", 5)
    assert len(broker.deliveries_for("c2")) == 1


# 15 --------------------------------------------------------------------


def test_main_self_check():
    path = os.path.join(os.path.dirname(__file__), "..", "mqtt_broker.py")
    proc = subprocess.run(
        [sys.executable, path], capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "mqtt-broker OK" in proc.stdout
