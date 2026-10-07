"""Tests for sse_manager (Server-Sent Events bookkeeping)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from sse_manager import (
    AUDIT_SCHEMA,
    BadEventError,
    BadStreamError,
    ClosedStreamError,
    DuplicateStreamError,
    EVENT_TYPE_MESSAGE,
    SSE_MANAGER_SCHEMA,
    SSE_MANAGER_VERSION,
    SeqOrderError,
    SSEManager,
    SSEManagerError,
    UnknownStreamError,
    sse_manager_audit_event,
)


def _mod():
    return SSEManager(seed="t")


def test_version_and_schema_pins():
    assert SSE_MANAGER_VERSION == "sse-manager.v1"
    assert SSE_MANAGER_SCHEMA == "northstar.sse-manager.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def _module_path():
    return Path(__file__).resolve().parent.parent / "sse_manager.py"


def test_stdlib_only_ast():
    tree = ast.parse(_module_path().read_text())
    allowed = {"canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in {
                    "hashlib", "hmac", "threading", "dataclasses",
                    "typing", "__future__", "json",
                } | allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            assert mod in {
                "hashlib", "hmac", "threading", "dataclasses",
                "typing", "__future__", "json",
            } | allowed, node.module


def test_main_selfcheck():
    r = subprocess.run(
        [sys.executable, str(_module_path())],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("sse-manager OK:")


def test_stream_roundtrip():
    m = _mod()
    s = m.stream("s1", 0, topic="ops", retry_ms=3000)
    assert s.stream_id == "s1" and s.topic == "ops"
    assert s.retry_ms == 3000 and s.state == "open"
    assert s.verify(seed="t")
    assert m.stream_record("s1") is s
    assert m.stream_ids() == ("s1",)
    assert m.open_ids() == ("s1",)


def test_stream_defaults():
    m = _mod()
    s = m.stream("s1", 5)
    assert s.topic == "" and s.retry_ms is None
    assert m.stream("s2", 6, topic="x").stream_id == "s2"


def test_stream_duplicate_refused():
    m = _mod()
    m.stream("s1", 0)
    with pytest.raises(DuplicateStreamError):
        m.stream("s1", 1)
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds[-1] == "sse.rejected"


def test_stream_bad_inputs():
    m = _mod()
    with pytest.raises(SSEManagerError):
        m.stream("", 0)
    with pytest.raises(SSEManagerError):
        m.stream("s1", 1, retry_ms=True)
    with pytest.raises(BadStreamError):
        m.stream("s1", 2, retry_ms=-1)
    with pytest.raises(BadStreamError):
        m.stream("s1", 3, topic=123)
    # unknown lookups
    with pytest.raises(UnknownStreamError):
        m.stream_record("nope")


def test_event_roundtrip():
    m = _mod()
    m.stream("s1", 0)
    e = m.event("s1", "hello", 1)
    assert e.event_seq_id == "evt-1"
    assert e.event_type == EVENT_TYPE_MESSAGE
    assert e.dispatch_seq == 1
    assert e.verify(seed="t")
    assert m.event_record("evt-1") is e
    assert m.event_ids("s1") == ("evt-1",)


def test_event_multiline_and_type():
    m = _mod()
    m.stream("s1", 0)
    e = m.event("s1", ["l1", "l2"], 1, event_type="update", comment="note")
    assert e.event_seq_id == "evt-1"
    wire = m.as_wire("evt-1", 1)
    assert wire == "event: update\nid: evt-1\ndata: l1\ndata: l2\n: note\n\n"


def test_event_custom_id():
    m = _mod()
    m.stream("s1", 0)
    e = m.event("s1", "x", 1, event_id="res-42")
    assert e.event_seq_id == "res-42"
    e2 = m.event("s1", "y", 2)
    assert e2.event_seq_id == "evt-1"  # auto ids independent of custom
    with pytest.raises(BadEventError):
        m.event("s1", "z", 3, event_id="res-42")


def test_event_bad_inputs():
    m = _mod()
    m.stream("s1", 0)
    with pytest.raises(UnknownStreamError):
        m.event("nope", "x", 1)
    with pytest.raises(BadEventError):
        m.event("s1", "", 2)
    with pytest.raises(BadEventError):
        m.event("s1", ["a", ""], 3)
    with pytest.raises(BadEventError):
        m.event("s1", 123, 4)
    with pytest.raises(BadEventError):
        m.event("s1", "bad\rline", 5)
    with pytest.raises(SSEManagerError):
        m.event("s1", "x", 6, event_type="has\nnewline")


def test_event_on_closed_stream_refused():
    m = _mod()
    m.stream("s1", 0)
    m.close("s1", 1)
    with pytest.raises(ClosedStreamError):
        m.event("s1", "late", 2)
    with pytest.raises(ClosedStreamError):
        m.heartbeat("s1", 3)


def test_close_roundtrip_and_terminal():
    m = _mod()
    m.stream("s1", 0)
    c = m.close("s1", 1, reason="done")
    assert c.verify(seed="t") and c.reason == "done"
    assert m.stream_record("s1").state == "closed"
    assert m.open_ids() == ()
    with pytest.raises(ClosedStreamError):
        m.close("s1", 2)
    with pytest.raises(UnknownStreamError):
        m.close("nope", 3)


def test_heartbeat_roundtrip():
    m = _mod()
    m.stream("s1", 0)
    hb = m.heartbeat("s1", 1)
    assert hb.heartbeat_id == "hb-1" and hb.verify(seed="t")
    hb2 = m.heartbeat("s1", 2, comment="alive")
    assert hb2.heartbeat_id == "hb-2"
    with pytest.raises(SSEManagerError):
        m.heartbeat("s1", 3, comment="bad\nline")


def test_replay_resumption():
    m = _mod()
    m.stream("s1", 0)
    m.event("s1", "a", 1)
    m.event("s1", "b", 2)
    m.event("s1", "c", 3)
    all_evts = m.replay("s1", 4)
    assert [e.event_seq_id for e in all_evts] == ["evt-1", "evt-2", "evt-3"]
    after = m.replay("s1", 5, last_event_id="evt-2")
    assert [e.event_seq_id for e in after] == ["evt-3"]
    # unknown cursor: conservative resync, everything returned
    assert len(m.replay("s1", 6, last_event_id="bogus")) == 3
    # limit honored; read does not consume seq
    assert len(m.replay("s1", 7, limit=2)) == 2
    with pytest.raises(UnknownStreamError):
        m.replay("nope", 8)


def test_as_wire_default_message_omits_event_line():
    m = _mod()
    m.stream("s1", 0, retry_ms=1500)
    m.event("s1", "ping", 1)
    assert m.as_wire("evt-1", 1) == "id: evt-1\ndata: ping\nretry: 1500\n\n"
    with pytest.raises(BadEventError):
        m.as_wire("bogus", 1)


def test_seq_ordering():
    m = _mod()
    m.stream("s1", 0)
    with pytest.raises(SeqOrderError):
        m.stream("s2", 0)
    with pytest.raises(SSEManagerError):
        m.stream("s2", True)
    with pytest.raises(SSEManagerError):
        m.stream("s2", -1)
    with pytest.raises(SSEManagerError):
        m.stream("s2", "x")


def test_failed_mutation_consumes_seq():
    m = _mod()
    m.stream("s1", 0)
    with pytest.raises(DuplicateStreamError):
        m.stream("s1", 1)
    # seq 1 was consumed by the failed mutation
    with pytest.raises(SeqOrderError):
        m.stream("s2", 1)
    s2 = m.stream("s2", 2)
    assert s2.stream_id == "s2"


def test_audit_shapes_and_bad_kind():
    m = _mod()
    m.stream("s1", 0, topic="t")
    m.event("s1", "d", 1)
    m.heartbeat("s1", 2)
    m.close("s1", 3)
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds == [
        "sse.stream-opened", "sse.event-emitted", "sse.heartbeat", "sse.stream-closed",
    ]
    for e in m.audit_log():
        assert e["schema"] == AUDIT_SCHEMA
        assert "data" not in e["detail"] and "comment" not in e["detail"]
        assert "payload" not in e["detail"]
    with pytest.raises(SSEManagerError):
        sse_manager_audit_event("bogus", 9)
    with pytest.raises(SSEManagerError):
        sse_manager_audit_event("sse.event-emitted", 9, data="leak")


def test_stats_view():
    m = _mod()
    m.stream("s1", 0)
    m.stream("s2", 1)
    m.event("s1", "x", 2)
    m.heartbeat("s1", 3)
    m.close("s2", 4)
    st = m.stats(5)
    assert st == {"streams": 2, "open": 1, "closed": 1, "events": 1, "heartbeats": 1}


def test_cross_instance_determinism():
    a = SSEManager(seed="z")
    b = SSEManager(seed="z")
    a.stream("s", 0, topic="t")
    b.stream("s", 0, topic="t")
    ea = a.event("s", "d", 1)
    eb = b.event("s", "d", 1)
    assert ea.digest == eb.digest and ea.verify(seed="z")


def test_data_digest_is_stable_and_hashed():
    m = _mod()
    m.stream("s1", 0)
    e = m.event("s1", "secret-payload", 1)
    assert e.data_digest.startswith("sha256:")
    assert "secret-payload" not in e.data_digest
    assert "secret-payload" not in repr(m.audit_log())
