"""Tests for websocket_manager."""

from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import websocket_manager as wm
from websocket_manager import (
    WebSocketManager,
    websocket_manager_audit_event,
    WEBSOCKET_MANAGER_VERSION,
    WEBSOCKET_MANAGER_SCHEMA,
    AUDIT_SCHEMA,
    REASON_CLOSE,
    KIND_REJECTED,
)

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def test_version_and_schema_pins():
    assert WEBSOCKET_MANAGER_VERSION == "websocket-manager.v1"
    assert WEBSOCKET_MANAGER_SCHEMA == "northstar.websocket-manager.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only_ast():
    src = Path(wm.__file__).read_text()
    tree = ast.parse(src)
    allowed = {
        "hashlib", "threading", "dataclasses", "typing",
        "__future__", "json", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_connect_roundtrip_and_verify():
    m = WebSocketManager()
    rec = m.connect("c1", 1, client="web", origin="example.com")
    assert rec.connection_id == "c1"
    assert rec.verify()
    assert m.connection("c1") is rec
    assert m.is_connected("c1")


def test_connect_duplicate_and_bad_inputs():
    m = WebSocketManager()
    m.connect("c1", 1)
    with pytest.raises(wm.DuplicateConnectionError):
        m.connect("c1", 2)
    with pytest.raises(wm.BadConnectionError):
        m.connect("   ", 3)
    with pytest.raises(wm.SeqOrderError):
        m.connect("c2", 2)  # rewind (2 <= last taken seq 2... use 2 after dup took it)
    with pytest.raises(wm.SeqOrderError):
        m.connect("c2", -1)


def test_disconnect_terminal_and_room_release():
    m = WebSocketManager()
    m.connect("c1", 1)
    m.room("c1", "lobby", 2)
    d = m.disconnect("c1", 3, reason=REASON_CLOSE)
    assert d.rooms_released == ("lobby",)
    assert d.verify()
    assert not m.is_connected("c1")
    with pytest.raises(wm.TerminalConnectionError):
        m.disconnect("c1", 4)
    with pytest.raises(wm.UnknownConnectionError):
        m.disconnect("ghost", 5)


def test_disconnect_bad_reason():
    m = WebSocketManager()
    m.connect("c1", 1)
    with pytest.raises(wm.WebSocketManagerError):
        m.disconnect("c1", 2, reason="nope")


def test_room_join_leave_cycle():
    m = WebSocketManager()
    m.connect("c1", 1)
    mem = m.room("c1", "lobby", 2)
    assert mem.verify()
    assert m.members("lobby") == ("c1",)
    assert m.rooms_of("c1") == ("lobby",)
    with pytest.raises(wm.DuplicateMembershipError):
        m.room("c1", "lobby", 3)
    lv = m.leave("c1", "lobby", 4)
    assert lv.verify()
    assert m.members("lobby") == ()
    with pytest.raises(wm.UnknownMembershipError):
        m.leave("c1", "lobby", 5)


def test_room_bad_names():
    m = WebSocketManager()
    m.connect("c1", 1)
    with pytest.raises(wm.BadRoomError):
        m.room("c1", "", 2)
    with pytest.raises(wm.BadRoomError):
        m.room("c1", "has space", 3)
    with pytest.raises(wm.BadRoomError):
        m.room("c1", "x" * 129, 4)
    with pytest.raises(wm.UnknownConnectionError):
        m.room("ghost", "lobby", 5)


def test_broadcast_roundtrip_and_verify():
    m = WebSocketManager()
    m.connect("c1", 1)
    m.connect("c2", 2)
    m.room("c1", "lobby", 3)
    m.room("c2", "lobby", 4)
    bc = m.broadcast("lobby", DIGEST, 5)
    assert bc.recipients == ("c1", "c2")
    assert bc.delivered == ("c1", "c2")
    assert bc.failed == ()
    assert bc.verify()
    rec = m.broadcast_record("bc-1")
    assert rec is bc


def test_broadcast_exclude_and_unknown_room():
    m = WebSocketManager()
    m.connect("c1", 1)
    m.connect("c2", 2)
    m.room("c1", "lobby", 3)
    m.room("c2", "lobby", 4)
    bc = m.broadcast("lobby", DIGEST, 5, exclude=("c2",))
    assert bc.recipients == ("c1",)
    with pytest.raises(wm.UnknownRoomError):
        m.broadcast("nope", DIGEST, 6)
    with pytest.raises(wm.BadDigestError):
        m.broadcast("lobby", "not-a-digest", 7)


def test_broadcast_emitter_failure_modes():
    # emitter returning False -> failed list is data
    m = WebSocketManager(emitter=lambda cid, d: False)
    m.connect("c1", 1)
    m.room("c1", "lobby", 2)
    bc = m.broadcast("lobby", DIGEST, 3)
    assert bc.delivered == ()
    assert bc.failed == ("c1",)
    # emitter raising -> fail-closed
    def boom(cid, d):
        raise RuntimeError("down")
    m2 = WebSocketManager(emitter=boom)
    m2.connect("c1", 1)
    m2.room("c1", "lobby", 2)
    with pytest.raises(wm.BadEmitterError):
        m2.broadcast("lobby", DIGEST, 3)


def test_send_roundtrip_and_terminal_refusal():
    m = WebSocketManager()
    m.connect("c1", 1)
    s = m.send("c1", DIGEST, 2)
    assert s.verify()
    assert s.delivered is True
    m.disconnect("c1", 3)
    with pytest.raises(wm.TerminalConnectionError):
        m.send("c1", DIGEST, 4)
    with pytest.raises(wm.UnknownConnectionError):
        m.send("ghost", DIGEST, 5)


def test_seq_discipline_failed_mutation_consumes_seq():
    m = WebSocketManager()
    m.connect("c1", 1)
    with pytest.raises(wm.DuplicateConnectionError):
        m.connect("c1", 2)  # consumes 2
    with pytest.raises(wm.SeqOrderError):
        m.connect("c2", 2)  # rewind
    m.connect("c2", 3)  # ok


def test_audit_shapes_and_banned_keys():
    m = WebSocketManager()
    m.connect("c1", 1)
    ev = websocket_manager_audit_event(
        "websocket.connected", {"connection_id": "c1"}, 1
    )
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == "websocket-manager.v1"
    with pytest.raises(wm.WebSocketManagerError):
        websocket_manager_audit_event("bogus", {}, 2)
    with pytest.raises(wm.WebSocketManagerError):
        websocket_manager_audit_event(
            "websocket.broadcast", {"payload": "x"}, 3
        )
    kinds = {e["kind"] for e in m.audit_log()}
    assert "websocket.connected" in kinds


def test_views_and_concurrency():
    m = WebSocketManager()
    assert m.stats()["connections"] == 0
    def worker(n):
        m.connect(f"c{n}", n + 1)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m.stats()["connections"] == 4
    assert len(m.connection_ids()) == 4
    d = m.as_dict()
    assert d["version"] == "websocket-manager.v1"


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, str(Path(wm.__file__))],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert "websocket-manager OK" in r.stdout
