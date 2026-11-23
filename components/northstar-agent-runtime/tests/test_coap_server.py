"""Tests for coap_server.py -- simulated RFC 7252/7641/7959 ledger."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, "..")
import coap_server as cs


# ---------------------------------------------------------------------------
# pins / stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert cs.COAP_SERVER_VERSION == "coap-server.v1"
    assert cs.SCHEMA_PIN == "northstar.coap-server.v1"
    assert cs.AUDIT_FORMAT == "audit.ndjson/1"


def test_method_vocabulary():
    assert cs._METHODS == frozenset(
        {"GET", "POST", "PUT", "DELETE", "FETCH", "PATCH", "iPATCH"}
    )
    assert cs._SAFE_METHODS == frozenset({"GET", "FETCH"})
    assert cs._IDEMPOTENT_METHODS == frozenset(
        {"GET", "PUT", "DELETE", "FETCH", "iPATCH"}
    )


def test_stdlib_only():
    tree = ast.parse(open(cs.__file__).read())
    allowed = {
        "hashlib",
        "hmac",
        "json",
        "math",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
    }
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.asname or a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= allowed, f"non-stdlib imports: {imported - allowed}"


# ---------------------------------------------------------------------------
# resource()
# ---------------------------------------------------------------------------


def test_resource_roundtrip():
    srv = cs.CoAPServer()
    r = srv.resource("/s/temp", 0, methods=("GET", "PUT"),
                     content_format="text/plain", observe_allowed=True)
    assert r.path == "/s/temp"
    assert r.methods == ("GET", "PUT")  # sorted
    assert r.content_format == "text/plain"
    assert r.observe_allowed is True
    assert r.digest.startswith("sha256:")
    assert srv.resource_record("/s/temp") == r
    assert srv.resources() == ("/s/temp",)


def test_resource_duplicate_refused():
    srv = cs.CoAPServer()
    srv.resource("/a", 0)
    with pytest.raises(cs.DuplicateResourceError):
        srv.resource("/a", 1)


@pytest.mark.parametrize(
    "bad",
    ["", "no-slash", "/has space", "/a//b", "/./x", "/../x", "/"],
)
def test_resource_bad_paths(bad):
    srv = cs.CoAPServer()
    with pytest.raises((cs.BadResourceError, ValueError, TypeError)):
        srv.resource(bad, 0)


def test_resource_bad_methods():
    srv = cs.CoAPServer()
    with pytest.raises(cs.BadResourceError):
        srv.resource("/a", 0, methods=("TELEPORT",))
    with pytest.raises(cs.BadResourceError):
        srv.resource("/b", 1, methods=())
    with pytest.raises(TypeError):
        srv.resource("/c", 2, methods="GET")  # bare string refused


def test_resource_unknown_lookup():
    srv = cs.CoAPServer()
    with pytest.raises(cs.UnknownResourceError):
        srv.resource_record("/nope")


# ---------------------------------------------------------------------------
# observe (RFC 7641)
# ---------------------------------------------------------------------------


def test_observe_roundtrip():
    srv = cs.CoAPServer()
    srv.resource("/s/hum", 0, observe_allowed=True)
    o = srv.observe("/s/hum", "obs-1", 1)
    assert o.observe_seq == 0
    assert o.active is True
    assert o.digest.startswith("sha256:")
    cur = srv.observation("/s/hum", "obs-1")
    assert cur.observe_seq == 0 and cur.active


def test_observe_not_allowed():
    srv = cs.CoAPServer()
    srv.resource("/cmd", 0)  # observe_allowed defaults False
    with pytest.raises(cs.ObserveNotAllowedError):
        srv.observe("/cmd", "obs-1", 1)


def test_observe_unknown_resource():
    srv = cs.CoAPServer()
    with pytest.raises(cs.UnknownResourceError):
        srv.observe("/ghost", "obs-1", 0)


def test_observe_duplicate_refused():
    srv = cs.CoAPServer()
    srv.resource("/s/hum", 0, observe_allowed=True)
    srv.observe("/s/hum", "obs-1", 1)
    with pytest.raises(cs.DuplicateObservationError):
        srv.observe("/s/hum", "obs-1", 2)


def test_cancel_observe():
    srv = cs.CoAPServer()
    srv.resource("/s/hum", 0, observe_allowed=True)
    srv.observe("/s/hum", "obs-1", 1)
    c = srv.cancel_observe("/s/hum", "obs-1", 2)
    assert c.digest.startswith("sha256:")
    assert srv.observations() == ()
    with pytest.raises(cs.UnknownObservationError):
        srv.cancel_observe("/s/hum", "obs-1", 3)


def test_reobserve_after_cancel_allowed():
    srv = cs.CoAPServer()
    srv.resource("/s/hum", 0, observe_allowed=True)
    srv.observe("/s/hum", "obs-1", 1)
    srv.cancel_observe("/s/hum", "obs-1", 2)
    o2 = srv.observe("/s/hum", "obs-1", 3)
    assert o2.active and o2.observe_seq == 0


def test_observations_view_filtered():
    srv = cs.CoAPServer()
    srv.resource("/a", 0, observe_allowed=True)
    srv.resource("/b", 1, observe_allowed=True)
    srv.observe("/a", "x", 2)
    srv.observe("/b", "y", 3)
    assert len(srv.observations()) == 2
    assert len(srv.observations("/a")) == 1
    assert srv.observations("/a")[0].observer_id == "x"


# ---------------------------------------------------------------------------
# notify()
# ---------------------------------------------------------------------------


def test_notify_fanout_and_seq():
    srv = cs.CoAPServer()
    srv.resource("/s/temp", 0, observe_allowed=True)
    srv.observe("/s/temp", "b", 1)
    srv.observe("/s/temp", "a", 2)
    rep = srv.notify("/s/temp", 3, payload={"t": 22.0})
    assert rep.observer_ids == ("a", "b")  # sorted
    assert rep.notifications[0].observe_seq == 1
    assert rep.notifications[1].observe_seq == 1
    # msg_id monotonic
    assert rep.notifications[1].msg_id == rep.notifications[0].msg_id + 1
    rep2 = srv.notify("/s/temp", 4)
    assert rep2.notifications[0].observe_seq == 2


def test_notify_msg_type_and_code():
    srv = cs.CoAPServer()
    srv.resource("/s/temp", 0, observe_allowed=True)
    srv.observe("/s/temp", "a", 1)
    rep = srv.notify("/s/temp", 2, msg_type=cs.MSG_CON, code=cs.RESP_204_CHANGED)
    n = rep.notifications[0]
    assert n.msg_type == "CON" and n.code == "2.04"
    with pytest.raises(cs.BadResponseError):
        srv.notify("/s/temp", 3, msg_type="SMOKE")
    with pytest.raises(cs.BadResponseError):
        srv.notify("/s/temp", 4, code="7.77")


def test_notify_unknown_resource():
    srv = cs.CoAPServer()
    with pytest.raises(cs.UnknownResourceError):
        srv.notify("/ghost", 0)


def test_notify_no_observers_empty_report():
    srv = cs.CoAPServer()
    srv.resource("/s/temp", 0, observe_allowed=True)
    rep = srv.notify("/s/temp", 1)
    assert rep.observer_ids == ()
    assert rep.notifications == ()


def test_observe_seq_wraps_at_2pow24():
    srv = cs.CoAPServer()
    srv.resource("/s/temp", 0, observe_allowed=True)
    srv.observe("/s/temp", "a", 1)
    entry = srv._resources["/s/temp"]["observers"]["a"]
    entry["seq"] = (1 << 24) - 1
    rep = srv.notify("/s/temp", 2)
    assert rep.notifications[0].observe_seq == 0


# ---------------------------------------------------------------------------
# block() (RFC 7959)
# ---------------------------------------------------------------------------


def test_block_single_complete():
    srv = cs.CoAPServer()
    srv.resource("/fw", 0)
    b = srv.block("/fw", 1, block_no=0, more=False, block_size=1024, payload="all")
    assert b.state == "complete"
    assert b.blocks_received == 1


def test_block_chain_continuity():
    srv = cs.CoAPServer()
    srv.resource("/fw", 0)
    b0 = srv.block("/fw", 1, block_no=0, more=True, block_size=64, payload="p0")
    assert b0.state == "in-progress"
    st = srv.block_state("/fw")
    assert st == {"path": "/fw", "next_block_no": 1, "block_size": 64, "blocks_received": 1}
    b1 = srv.block("/fw", 2, block_no=1, more=False, block_size=64, payload="p1")
    assert b1.state == "complete" and b1.blocks_received == 2
    assert srv.block_state("/fw") is None


def test_block_out_of_order_refused():
    srv = cs.CoAPServer()
    srv.resource("/fw", 0)
    srv.block("/fw", 1, block_no=0, more=True, block_size=64, payload="p0")
    with pytest.raises(cs.BadBlockError):
        srv.block("/fw", 2, block_no=2, more=False, block_size=64, payload="p2")


def test_block_new_transfer_must_start_at_zero():
    srv = cs.CoAPServer()
    srv.resource("/fw", 0)
    with pytest.raises(cs.BadBlockError):
        srv.block("/fw", 1, block_no=5, more=True, block_size=64, payload="p5")


def test_block_size_change_mid_transfer_refused():
    srv = cs.CoAPServer()
    srv.resource("/fw", 0)
    srv.block("/fw", 1, block_no=0, more=True, block_size=64, payload="p0")
    with pytest.raises(cs.BadBlockError):
        srv.block("/fw", 2, block_no=1, more=False, block_size=128, payload="p1")


def test_block_bad_inputs():
    srv = cs.CoAPServer()
    srv.resource("/fw", 0)
    with pytest.raises(cs.BadBlockError):
        srv.block("/fw", 1, block_no=0, more=False, block_size=48, payload="x")
    with pytest.raises(cs.BadBlockError):
        srv.block("/fw", 2, block_no=1 << 20, more=False, block_size=64, payload="x")
    with pytest.raises(cs.UnknownResourceError):
        srv.block("/ghost", 3, block_no=0, more=False)


def test_block_two_sequential_transfers():
    srv = cs.CoAPServer()
    srv.resource("/fw", 0)
    srv.block("/fw", 1, block_no=0, more=True, block_size=16, payload="a")
    srv.block("/fw", 2, block_no=1, more=False, block_size=16, payload="b")
    # fresh transfer reuses the path cleanly
    b = srv.block("/fw", 3, block_no=0, more=True, block_size=32, payload="c")
    assert b.state == "in-progress" and b.blocks_received == 1


# ---------------------------------------------------------------------------
# seq discipline
# ---------------------------------------------------------------------------


def test_seq_ordering():
    srv = cs.CoAPServer()
    with pytest.raises(TypeError):
        srv.resource("/a", True)
    with pytest.raises(TypeError):
        srv.resource("/a", "0")
    with pytest.raises(ValueError):
        srv.resource("/a", -1)


def test_msg_id_wraps():
    srv = cs.CoAPServer()
    srv.resource("/s/temp", 0, observe_allowed=True)
    srv.observe("/s/temp", "a", 1)
    srv._msg_id = (1 << 16) - 1
    rep = srv.notify("/s/temp", 2)
    assert rep.notifications[0].msg_id == (1 << 16) - 1
    assert srv._msg_id == 0


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def test_audit_shapes():
    ev = cs.coap_server_audit_event("resource-registered", 3, path="/a")
    assert ev["format"] == "audit.ndjson/1"
    assert ev["kind"] == "resource-registered"
    assert ev["seq"] == 3
    assert ev["module"] == "coap-server.v1"
    assert ev["schema"] == "northstar.coap-server.v1"
    assert ev["detail"] == {"path": "/a"}


def test_audit_bad_kind():
    with pytest.raises(ValueError):
        cs.coap_server_audit_event("bogus", 0)
    with pytest.raises(TypeError):
        cs.coap_server_audit_event(True, 0)


# ---------------------------------------------------------------------------
# stats / views / main / concurrency
# ---------------------------------------------------------------------------


def test_stats():
    srv = cs.CoAPServer()
    srv.resource("/a", 0, observe_allowed=True)
    srv.resource("/b", 1)
    srv.observe("/a", "x", 2)
    srv.block("/b", 3, block_no=0, more=True, block_size=32, payload="p")
    st = srv.stats()
    assert st["resources"] == 2
    assert st["active_observations"] == 1
    assert st["in_flight_block_transfers"] == 1


def test_frozen_records():
    srv = cs.CoAPServer()
    r = srv.resource("/a", 0)
    with pytest.raises(Exception):
        r.path = "/b"  # frozen dataclass


def test_thread_safety_smoke():
    srv = cs.CoAPServer()
    srv.resource("/a", 0, observe_allowed=True)
    srv.observe("/a", "x", 1)
    errors = []

    def worker(n):
        try:
            for i in range(20):
                srv.notify("/a", 1000 + n * 20 + i)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # 80 notifications => observe_seq advanced 80
    assert srv.observation("/a", "x").observe_seq == 80


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, cs.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "coap-server OK" in proc.stdout
