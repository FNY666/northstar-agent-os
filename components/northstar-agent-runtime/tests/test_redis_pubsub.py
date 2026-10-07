"""Tests for redis_pubsub.py (15 tests)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from redis_pubsub import (
    AUDIT_SCHEMA,
    REDIS_PUBSUB_SCHEMA,
    REDIS_PUBSUB_VERSION,
    BadChannelError,
    BadPatternError,
    BadPayloadError,
    DuplicatePatternError,
    DuplicateSubscriptionError,
    RedisPubSub,
    RedisPubSubError,
    SeqOrderError,
    UnknownPatternError,
    UnknownSubscriptionError,
    _glob_match,
    redis_pubsub_audit_event,
)


def fresh():
    return RedisPubSub()


def _module_path():
    return Path(__file__).resolve().parent.parent / "redis_pubsub.py"


# 1. version / schema pins
def test_version_pins():
    assert REDIS_PUBSUB_VERSION == "redis-pubsub.v1"
    assert REDIS_PUBSUB_SCHEMA == "northstar.redis-pubsub.v1"


# 2. stdlib-only AST check
def test_stdlib_only():
    src = _module_path().read_text()
    tree = ast.parse(src)
    allowed = {
        "threading", "dataclasses", "typing", "__future__",
        "canonical_json", "hashlib", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. subscribe roundtrip + record verify
def test_subscribe_roundtrip():
    bus = fresh()
    rec = bus.subscribe("c1", "news", 1)
    assert rec.verify()
    assert rec.client_id == "c1" and rec.channel == "news"
    got = bus.subscription("c1", "news", 2)
    assert got.digest == rec.digest


# 4. duplicate subscribe refused
def test_duplicate_subscribe_refused():
    bus = fresh()
    bus.subscribe("c1", "news", 1)
    with pytest.raises(DuplicateSubscriptionError):
        bus.subscribe("c1", "news", 2)
    # failed mutation consumed its seq: next valid seq must exceed 2
    with pytest.raises(SeqOrderError):
        bus.subscribe("c1", "sports", 2)


# 5. bad channel table
def test_bad_channels():
    bus = fresh()
    for bad in ["", "   ", "has space", "with*star", "with?mark", "a[b",
                "x" * 257, "tab\there"]:
        with pytest.raises(RedisPubSubError):
            bus.subscribe("c1", bad, 1)
    # channel is lowercased/normalized
    rec = bus.subscribe("c1", "NEWS", 5)
    assert rec.channel == "news"


# 6. unsubscribe lifecycle + terminality
def test_unsubscribe_lifecycle():
    bus = fresh()
    bus.subscribe("c1", "news", 1)
    rec = bus.unsubscribe("c1", "news", 2)
    assert rec.verify()
    with pytest.raises(UnknownSubscriptionError):
        bus.subscription("c1", "news", 3)
    with pytest.raises(UnknownSubscriptionError):
        bus.unsubscribe("c1", "news", 4)


# 7. psubscribe / punsubscribe + bad patterns
def test_pattern_subscribe_cycle():
    bus = fresh()
    rec = bus.psubscribe("c1", "news.*", 1)
    assert rec.verify()
    assert bus.patterns_for("c1", 2) == ("news.*",)
    with pytest.raises(DuplicatePatternError):
        bus.psubscribe("c1", "news.*", 3)
    pun = bus.punsubscribe("c1", "news.*", 4)
    assert pun.verify()
    assert bus.patterns_for("c1", 5) == ()
    with pytest.raises(UnknownPatternError):
        bus.punsubscribe("c1", "news.*", 6)
    # character classes and escapes refused fail-closed
    for bad in ["a[bc]", "a\\b"]:
        with pytest.raises(BadPatternError):
            bus.psubscribe("c2", bad, 7)


# 8. publish fan-out: direct + pattern, double delivery for both
def test_publish_fanout():
    bus = fresh()
    bus.subscribe("direct", "news", 1)
    bus.subscribe("both", "news", 2)
    bus.psubscribe("both", "n*", 3)
    bus.psubscribe("pat", "n?ws", 4)
    rep = bus.publish("news", {"h": 1}, 5)
    assert rep.verify()
    assert rep.message_id == "msg-1"
    assert rep.channel_deliveries == 2
    assert rep.pattern_deliveries == 2
    assert rep.total_deliveries == 4
    # 'both' got the message twice (channel + pattern), Redis-faithfully
    kinds = [d.kind for d in bus.deliveries_for("both", 6)]
    assert kinds == ["channel", "pattern"]
    assert [d.kind for d in bus.deliveries_for("direct", 7)] == ["channel"]
    assert [d.kind for d in bus.deliveries_for("pat", 8)] == ["pattern"]


# 9. publish to empty channel books zero deliveries (Redis drops it)
def test_publish_no_subscribers():
    bus = fresh()
    rep = bus.publish("lonely", "hello", 1)
    assert rep.total_deliveries == 0
    assert rep.receivers == ()
    assert bus.stats(2)["messages"] == 1
    assert bus.stats(3)["deliveries"] == 0


# 10. glob semantics: * and ?
def test_glob_match():
    assert _glob_match("*", "anything")
    assert _glob_match("n*", "news")
    assert _glob_match("n?ws", "news")
    assert not _glob_match("n?ws", "nws")
    assert not _glob_match("news", "newspaper")
    assert _glob_match("a*b*c", "aXXbYYc")
    assert not _glob_match("a?c", "ac")


# 11. payload validation: bad payloads refused
def test_bad_payloads():
    bus = fresh()
    with pytest.raises(BadPayloadError):
        bus.publish("news", float("nan"), 1)
    with pytest.raises(BadPayloadError):
        bus.publish("news", float("inf"), 2)
    with pytest.raises(BadPayloadError):
        bus.publish("news", {1: "x"}, 3)
    with pytest.raises(BadPayloadError):
        bus.publish("news", {"n": 2**53}, 4)
    with pytest.raises(BadPayloadError):
        bus.publish("news", 42, 5)
    # good payloads: str, bytes, mapping, list
    for i, ok in enumerate(["s", b"b", {"a": 1}, [1, 2]]):
        bus.publish("news", ok, 6 + i)
    # payload bytes retrievable host-side, digest pinned
    msg = bus.message("msg-1", 10)
    assert msg.payload_digest.startswith("sha256:")
    assert msg.verify()


# 12. seq discipline: rewind / bool refused, views don't consume
def test_seq_discipline():
    bus = fresh()
    bus.subscribe("c1", "news", 1)
    with pytest.raises(SeqOrderError):
        bus.subscribe("c1", "sports", 1)  # rewind
    with pytest.raises(SeqOrderError):
        bus.subscribe("c1", "sports", True)  # bool
    bus.subscriptions_for("c1", 1)  # view: same seq OK, not consumed
    bus.subscribe("c1", "sports", 2)  # still fine after views
    assert bus.subscriptions_for("c1", 3) == ("news", "sports")


# 13. audit shapes + payload leak ban + bad kind
def test_audit_shapes():
    bus = fresh()
    bus.subscribe("c1", "news", 1)
    bus.publish("news", "secret-bytes", 2)
    kinds = [row["kind"] for row in bus.audit_log()]
    assert kinds == [
        "redis-pubsub.subscribed",
        "redis-pubsub.published",
        "redis-pubsub.delivered",
    ]
    for row in bus.audit_log():
        assert row["schema"] == AUDIT_SCHEMA
        assert "payload" not in row["detail"]
    with pytest.raises(RedisPubSubError):
        redis_pubsub_audit_event("bogus", {}, 3)
    with pytest.raises(RedisPubSubError):
        redis_pubsub_audit_event("redis-pubsub.published",
                                 {"payload": "leak"}, 3)


# 14. views: channel subscribers, stats
def test_views():
    bus = fresh()
    bus.subscribe("a", "news", 1)
    bus.subscribe("b", "news", 2)
    bus.psubscribe("c", "*", 3)
    assert bus.channel_subscribers("news", 4) == ("a", "b")
    st = bus.stats(5)
    assert st == {"subscriptions": 2, "pattern_subscriptions": 1,
                  "messages": 0, "deliveries": 0, "clients": 3}


# 15. main() self-check
def test_main_self_check():
    mod = _module_path()
    out = subprocess.run([sys.executable, str(mod)], capture_output=True,
                         text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert "redis-pubsub OK" in out.stdout
