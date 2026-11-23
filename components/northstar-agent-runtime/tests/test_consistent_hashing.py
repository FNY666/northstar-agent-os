"""Targeted tests for consistent_hashing.py (house style)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

MODULE_DIR = Path(__file__).resolve().parent.parent
MODULE = MODULE_DIR / "consistent_hashing.py"
sys.path.insert(0, str(MODULE_DIR))

import consistent_hashing as ch  # noqa: E402


def make_ring(replicas=8):
    return ch.ConsistentHashing(replicas=replicas)


def test_version_and_schema_pins():
    assert ch.CONSISTENT_HASHING_VERSION == "consistent-hashing.v1"
    assert ch.CONSISTENT_HASHING_SCHEMA == "northstar.consistent-hashing.v1"
    assert ch.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only_ast():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.asname or a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.names[0].asname or node.module.split(".")[0])
    allowed = {
        "hashlib", "threading", "bisect", "dataclass", "dataclasses",
        "typing", "Any", "Dict", "List", "Mapping", "Tuple",
        "__future__", "annotations", "canonical_json", "json",
        "northstar_agent_runtime",
    }
    assert imported <= allowed, imported - allowed


def test_add_roundtrip_verify():
    ring = make_ring()
    rec = ring.add("node-1", 1)
    assert rec.verify()
    assert rec.node_id == "node-1"
    assert rec.weight == 1
    assert len(rec.vnode_positions) == 8
    assert ring.ring_size() == 8
    assert ring.node("node-1") == rec


def test_add_vnode_positions_deterministic():
    r1 = make_ring()
    r2 = make_ring()
    a = r1.add("n1", 1)
    b = r2.add("n1", 1)
    assert a.vnode_positions == b.vnode_positions
    assert a.digest == b.digest


def test_add_weight_scales_vnodes():
    ring = make_ring()
    ring.add("light", 1, weight=1)
    ring.add("heavy", 2, weight=3)
    assert ring.ring_size() == 8 + 24


def test_add_bad_inputs():
    ring = make_ring()
    for bad in ("", "a b", "a\tb", "x" * 257, None, 123, True):
        with pytest.raises(ch.ConsistentHashingError):
            ring.add(bad, 10)
    for bad_w in (0, -1, True, 1.5, "2", None, 1025):
        with pytest.raises(ch.ConsistentHashingError):
            ring.add("n", 20 + hash(str(bad_w)) % 1000, weight=bad_w)
    # rejections consumed their seqs: next fresh seq must still exceed them
    rec = ring.add("ok", 10_000)
    assert rec.verify()


def test_add_duplicate_refused_and_seq_consumed():
    ring = make_ring()
    ring.add("dup", 1)
    with pytest.raises(ch.DuplicateNodeError):
        ring.add("dup", 2)
    kinds = [e["kind"] for e in ring.audit_log()]
    assert ch.KIND_REJECTED in kinds
    with pytest.raises(ch.SeqOrderError):
        ring.add("other", 2)  # seq 2 already consumed by the refusal


def test_remove_roundtrip_verify():
    ring = make_ring()
    ring.add("gone", 1)
    rec = ring.remove("gone", 2)
    assert rec.verify()
    assert ring.node_ids() == ()
    assert ring.ring_size() == 0
    with pytest.raises(ch.UnknownNodeError):
        ring.node("gone")


def test_remove_readd_allowed():
    ring = make_ring()
    ring.add("flap", 1)
    ring.remove("flap", 2)
    rec = ring.add("flap", 3)
    assert rec.verify() and ring.node_ids() == ("flap",)


def test_remove_unknown_refused():
    ring = make_ring()
    with pytest.raises(ch.UnknownNodeError):
        ring.remove("ghost", 1)
    assert ch.KIND_REJECTED in [e["kind"] for e in ring.audit_log()]


def test_locate_owner_is_first_clockwise():
    ring = make_ring()
    ring.add("a", 1)
    ring.add("b", 2)
    ring.add("c", 3)
    for key in ("user-1", "user-2", "order-99", "blob/xyz"):
        rep = ring.locate(key, 10)
        assert rep.verify()
        assert rep.owner in ("a", "b", "c")
        assert rep.preference_list[0] == rep.owner
    # deterministic: two rings, same placement
    other = make_ring()
    for n, s in (("a", 1), ("b", 2), ("c", 3)):
        other.add(n, s)
    for key in ("user-1", "user-2", "order-99", "blob/xyz"):
        assert ring.locate(key, 10).owner == other.locate(key, 10).owner


def test_locate_preference_list_distinct_replicas():
    ring = make_ring()
    ring.add("a", 1)
    ring.add("b", 2)
    ring.add("c", 3)
    rep = ring.locate("key-1", 10, replicas=3)
    assert rep.preference_list == tuple(rep.preference_list)
    assert len(set(rep.preference_list)) == 3
    # cap at node count: no duplicates even when replicas > nodes
    rep2 = ring.locate("key-1", 11, replicas=99)
    assert len(set(rep2.preference_list)) == 3


def test_locate_empty_ring_fail_closed():
    ring = make_ring()
    with pytest.raises(ch.EmptyRingError):
        ring.locate("key", 1)
    # single node serves all keys
    ring.add("solo", 2)
    assert ring.locate("anything", 3).owner == "solo"


def test_locate_minimal_disruption():
    ring = make_ring()
    for i in range(4):
        ring.add(f"n{i}", i + 1)
    keys = [f"key-{i}" for i in range(200)]
    before = {k: ring.locate(k, 10).owner for k in keys}
    ring.add("n4", 11)
    after = {k: ring.locate(k, 12).owner for k in keys}
    moved = sum(1 for k in keys if before[k] != after[k])
    assert moved > 0  # new node takes some ranges
    assert moved < 200  # but most keys stay put (consistent, not full rehash)
    assert all(after[k] == "n4" for k in keys if before[k] != after[k])


def test_locate_is_pure_read():
    ring = make_ring()
    ring.add("a", 1)
    ring.locate("k", 2)
    ring.locate("k", 3)
    assert ring.stats()["audit_events"] == 1  # only the add wrote audit
    assert ring.stats()["last_seq"] == 1  # reads never consumed seq
    with pytest.raises(ch.SeqOrderError):
        ring.locate("k", "x")  # seq shape validated even for reads


def test_seq_ordering():
    ring = make_ring()
    ring.add("a", 5)
    with pytest.raises(ch.SeqOrderError):
        ring.add("b", 5)  # not strictly increasing
    with pytest.raises(ch.SeqOrderError):
        ring.add("b", 3)
    with pytest.raises(ch.SeqOrderError):
        ring.remove("a", 1)
    with pytest.raises(ch.SeqOrderError):
        ring.add("b", True)


def test_audit_shapes_and_bad_kind():
    ring = make_ring()
    ring.add("a", 1)
    ring.remove("a", 2)
    events = ring.audit_log()
    assert [e["kind"] for e in events] == [
        ch.KIND_NODE_ADDED,
        ch.KIND_NODE_REMOVED,
    ]
    for e in events:
        assert e["schema"] == ch.AUDIT_SCHEMA
        assert e["module"] == ch.CONSISTENT_HASHING_VERSION
        assert isinstance(e["seq"], int)
    with pytest.raises(ch.ConsistentHashingError):
        ch.consistent_hashing_audit_event("nope", {}, 1)
    # positions never cross the audit boundary
    with pytest.raises(ch.ConsistentHashingError):
        ch.consistent_hashing_audit_event(
            ch.KIND_NODE_ADDED, {"node_positions": [1, 2]}, 1
        )


def test_views_node_ids_sorted_ring_size_stats():
    ring = make_ring()
    ring.add("zebra", 1)
    ring.add("alpha", 2, weight=2)
    assert ring.node_ids() == ("alpha", "zebra")
    assert ring.ring_size() == 8 + 16
    stats = ring.stats()
    assert stats["nodes"] == 2
    assert stats["vnodes"] == 24
    assert stats["replicas"] == 8


def test_remove_consumes_all_vnodes():
    ring = make_ring()
    ring.add("a", 1, weight=2)
    ring.add("b", 2)
    before = ring.ring_size()
    ring.remove("a", 3)
    assert ring.ring_size() == before - 16
    # placement still works, owner always a live node
    rep = ring.locate("key", 4)
    assert rep.owner == "b"


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "consistent-hashing OK" in result.stdout
