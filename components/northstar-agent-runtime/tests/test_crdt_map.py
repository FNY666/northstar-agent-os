"""Tests for crdt_map: observed-remove map CRDT."""

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

import crdt_map
from crdt_map import (
    AUDIT_SCHEMA,
    CRDT_MAP_SCHEMA,
    CRDT_MAP_VERSION,
    BadKeyError,
    BadMergeError,
    BadReplicaError,
    BadValueError,
    CRDTMapError,
    crdt_map_audit_event,
    new_map,
)

HERE = Path(__file__).resolve()
MODULE = HERE.parent.parent / "crdt_map.py"

_ALLOWED_STDLIB = {
    "hashlib", "json", "dataclasses", "typing", "__future__",
}


def test_version_and_schema_pins():
    assert CRDT_MAP_VERSION == "crdt-map.v1"
    assert CRDT_MAP_SCHEMA == "northstar.crdt-map.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only_ast():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    imported.discard("canonical_json")  # guarded try/except fallback
    assert imported <= _ALLOWED_STDLIB, f"non-stdlib imports: {imported - _ALLOWED_STDLIB}"


def test_put_get_roundtrip():
    m = new_map("r1").put("k", {"n": 1})
    assert m.get("k") == {"n": 1}
    assert m.keys() == ("k",)
    assert len(m) == 1
    assert m.verify()


def test_put_replaces_observed_value():
    m = new_map("r1").put("k", "v1").put("k", "v2")
    assert m.get("k") == "v2"
    assert m.values("k") == ("v2",)
    assert m.verify()


def test_put_bad_inputs():
    m = new_map("r1")
    for bad_key in ("", True, 123, None):
        with pytest.raises(BadKeyError):
            m.put(bad_key, "v")
    for bad_replica in ("", True, 42, None):
        with pytest.raises(BadReplicaError):
            new_map(bad_replica)
    with pytest.raises(BadValueError):
        m.put("k", object())  # not JSON-serializable
    with pytest.raises(BadValueError):
        m.put("k", "x" * 70000)  # over the 64 KiB cap


def test_remove_roundtrip_and_absent_noop():
    m = new_map("r1").put("k", 1).remove("k")
    assert m.get("k") is None
    assert m.keys() == ()
    assert m.verify()
    # absent key is a no-op, not an error
    m2 = m.remove("never-there")
    assert m2.keys() == ()
    assert m2.verify()


def test_observed_remove_keeps_concurrent_add():
    # A puts, B puts concurrently (B never saw A's entry), A removes what
    # it observed, then merge: B's concurrent add survives.
    a = new_map("a").put("k", "a-val")
    b = new_map("b").put("k", "b-val")
    a_removed = a.remove("k")
    merged = a_removed.merge(b)
    assert merged.values("k") == ("b-val",)
    assert merged.verify()


def test_merge_commutative():
    a = new_map("a").put("x", 1).put("y", 2)
    b = new_map("b").put("x", 3).put("z", 4)
    # state-commutative: entries and clock converge; the merged map keeps
    # the caller's replica_id by design, so the identity pin differs.
    ab, ba = a.merge(b), b.merge(a)
    assert ab.entries == ba.entries
    assert ab.clock == ba.clock
    assert ab.verify() and ba.verify()


def test_merge_associative_and_idempotent():
    a = new_map("a").put("x", 1)
    b = new_map("b").put("y", 2)
    c = new_map("c").put("z", 3)
    assert a.merge(b).merge(c).digest == a.merge(b.merge(c)).digest
    assert a.merge(a).digest == a.digest
    assert a.merge(b).merge(a).digest == a.merge(b).digest


def test_merge_clock_takes_max():
    a = new_map("a").put("x", 1).put("x", 2)  # a's clock: a -> 2
    b = a.merge(new_map("b").put("y", 1))
    clock = dict(b.clock)
    assert clock["a"] == 2
    assert clock["b"] == 1


def test_merge_bad_operand():
    m = new_map("a")
    with pytest.raises(BadMergeError):
        m.merge({"not": "a map"})
    with pytest.raises(BadMergeError):
        m.merge(None)


def test_concurrent_puts_converge_deterministically():
    a = new_map("a").put("k", "from-a")
    b = new_map("b").put("k", "from-b")
    ab = a.merge(b)
    ba = b.merge(a)
    # both values survive; get is deterministic and order-independent
    assert set(ab.values("k")) == {"from-a", "from-b"}
    assert ab.get("k") == ba.get("k") == "from-a"  # smallest dot wins
    assert ab.verify() and ba.verify()


def test_entry_and_map_verify_reject_tampering():
    m = new_map("a").put("k", "v")
    entry = m.entries[0]
    assert entry.verify()
    tampered = entry.__class__(
        key=entry.key, dot=entry.dot, value_json='"evil"',
        digest=entry.digest, schema=entry.schema,
    )
    assert not tampered.verify()
    bad_map = m.__class__(
        replica_id=m.replica_id, clock=m.clock, entries=m.entries,
        digest="sha256:deadbeef", schema=m.schema,
    )
    assert not bad_map.verify()


def test_audit_shapes_and_bans():
    evt = crdt_map_audit_event(KIND_PUT, {"key": "k", "digest": "sha256:x"}, "r1")
    assert evt["schema"] == AUDIT_SCHEMA
    assert evt["kind"] == "crdt-map.put"
    assert evt["module"] == CRDT_MAP_VERSION
    with pytest.raises(CRDTMapError):
        crdt_map_audit_event("bogus", {}, "r1")
    with pytest.raises(CRDTMapError):
        crdt_map_audit_event(KIND_PUT, {"value": "leak"}, "r1")
    with pytest.raises(CRDTMapError):
        crdt_map_audit_event(KIND_PUT, {"value_json": "leak"}, "r1")


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "crdt-map OK: put, remove, merge, converge"


# silence linters about the imported-but-reexported names
assert json is not None
KIND_PUT = crdt_map.KIND_PUT
