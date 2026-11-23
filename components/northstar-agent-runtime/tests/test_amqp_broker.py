"""Tests for amqp_broker.py (RabbitMQ-shaped exchange/queue/bind routing)."""

from __future__ import annotations

import ast
import subprocess
import sys

import pytest

from amqp_broker import (
    AMQPBroker,
    AMQP_BROKER_VERSION,
    SCHEMA_PIN,
    BadBindingError,
    BadExchangeError,
    DuplicateBindingError,
    DuplicateExchangeError,
    DuplicateQueueError,
    PayloadError,
    SeqOrderError,
    UnknownExchangeError,
    UnknownQueueError,
    amqp_broker_audit_event,
)


def test_version_and_schema_pins():
    assert AMQP_BROKER_VERSION == "amqp-broker.v1"
    assert SCHEMA_PIN == "northstar.amqp-broker.v1"


def test_stdlib_only():
    tree = ast.parse(open("amqp_broker.py").read())
    allowed = {"hashlib", "threading", "dataclasses", "typing", "math", "__future__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_exchange_declare_roundtrip():
    b = AMQPBroker()
    rec = b.exchange("logs", "topic", 1)
    assert rec.exchange_id == "logs"
    assert rec.kind == "topic"
    assert rec.digest.startswith("sha256:")
    assert b.exchange_ids() == ("logs",)


def test_exchange_bad_kind():
    b = AMQPBroker()
    with pytest.raises(BadExchangeError):
        b.exchange("x", "roundrobin", 1)


def test_exchange_duplicate():
    b = AMQPBroker()
    b.exchange("x", "direct", 1)
    with pytest.raises(DuplicateExchangeError):
        b.exchange("x", "direct", 2)


def test_queue_declare_and_duplicate():
    b = AMQPBroker()
    b.queue("q1", 1)
    assert b.queue_ids() == ("q1",)
    with pytest.raises(DuplicateQueueError):
        b.queue("q1", 2)


def test_bind_direct_exact():
    b = AMQPBroker()
    b.exchange("e", "direct", 1)
    b.queue("q1", 2)
    b.queue("q2", 3)
    b.bind("e", "q1", "orders.created", 4)
    b.bind("e", "q2", "orders.shipped", 5)
    r1 = b.publish("e", "orders.created", {"n": 1}, 6)
    assert r1.routed_count == 1
    assert r1.routed[0].queue_id == "q1"
    r2 = b.publish("e", "orders.deleted", {"n": 2}, 7)
    assert r2.routed_count == 0


def test_bind_fanout_broadcast():
    b = AMQPBroker()
    b.exchange("e", "fanout", 1)
    b.queue("q1", 2)
    b.queue("q2", 3)
    b.bind("e", "q1", "", 4)
    b.bind("e", "q2", "ignored", 5)
    r = b.publish("e", "whatever.key", {"n": 1}, 6)
    assert r.routed_count == 2


def test_bind_topic_wildcards():
    b = AMQPBroker()
    b.exchange("e", "topic", 1)
    b.queue("all-logs", 2)
    b.queue("errors", 3)
    b.queue("one-level", 4)
    b.bind("e", "all-logs", "logs.#", 5)
    b.bind("e", "errors", "#.error", 6)
    b.bind("e", "one-level", "*.warn", 7)
    r = b.publish("e", "db.error", {"n": 1}, 8)
    assert {m.queue_id for m in r.routed} == {"errors"}
    r0 = b.publish("e", "logs.db.error", {"n": 1}, 9)
    assert {m.queue_id for m in r0.routed} == {"all-logs", "errors"}
    r2 = b.publish("e", "logs", {"n": 2}, 10)
    assert {m.queue_id for m in r2.routed} == {"all-logs"}
    r3 = b.publish("e", "app.warn", {"n": 3}, 11)
    assert {m.queue_id for m in r3.routed} == {"one-level"}
    r4 = b.publish("e", "deep.nested.error", {"n": 4}, 12)
    assert {m.queue_id for m in r4.routed} == {"errors"}


def test_bind_headers_exchange():
    b = AMQPBroker()
    b.exchange("e", "headers", 1)
    b.queue("q1", 2)
    b.queue("q2", 3)
    b.bind("e", "q1", headers={"format": "pdf", "x-match": "all"}, seq=4)
    b.bind("e", "q2", headers={"format": "zip", "x-match": "any"}, seq=5)
    r = b.publish("e", "", {"n": 1}, 6, headers={"format": "pdf"})
    assert {m.queue_id for m in r.routed} == {"q1"}
    r2 = b.publish("e", "", {"n": 2}, 7, headers={"format": "zip"})
    assert {m.queue_id for m in r2.routed} == {"q2"}
    with pytest.raises(BadBindingError):
        b.bind("e", "q1", "not-empty-key", seq=8)


def test_bind_errors():
    b = AMQPBroker()
    b.exchange("e", "direct", 1)
    b.queue("q", 2)
    with pytest.raises(UnknownExchangeError):
        b.bind("nope", "q", "k", 3)
    with pytest.raises(UnknownQueueError):
        b.bind("e", "nope", "k", 4)
    b.bind("e", "q", "k", 5)
    with pytest.raises(DuplicateBindingError):
        b.bind("e", "q", "k", 6)


def test_seq_strictly_increasing_and_burn():
    b = AMQPBroker()
    b.exchange("e", "direct", 1)
    with pytest.raises(SeqOrderError):
        b.queue("q", 1)  # not strictly increasing
    with pytest.raises(SeqOrderError):
        b.queue("q", True)  # bool is not an int seq
    with pytest.raises(DuplicateExchangeError):
        b.exchange("e", "direct", 2)  # fails, but consumes seq 2
    with pytest.raises(SeqOrderError):
        b.queue("q", 2)  # seq 2 already consumed


def test_publish_unknown_exchange_and_bad_payload():
    b = AMQPBroker()
    with pytest.raises(UnknownExchangeError):
        b.publish("nope", "k", {"n": 1}, 1)
    b.exchange("e", "direct", 2)
    with pytest.raises(PayloadError):
        b.publish("e", "k", float("nan"), 3)


def test_audit_shapes_and_bad_kind():
    ev = amqp_broker_audit_event("published", 9, exchange_id="e", routed_count=2)
    assert ev["kind"] == "amqp-broker.published"
    assert ev["seq"] == 9
    assert ev["version"] == "amqp-broker.v1"
    with pytest.raises(Exception):
        amqp_broker_audit_event("nope", 1)


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, "amqp_broker.py"],
        capture_output=True,
        text=True,
        cwd=".",
    )
    assert result.returncode == 0, result.stderr
    assert "amqp-broker OK" in result.stdout
