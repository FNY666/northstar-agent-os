"""15 targeted tests for index_manager (catalog layer over named secondary indexes)."""

import ast
import subprocess
import sys

import pytest

import index_manager as im
from index_manager import IndexManager


def test_version_and_schema_pins():
    assert im.INDEX_MANAGER_VERSION == "index-manager.v1"
    assert im.INDEX_MANAGER_SCHEMA == "northstar.index-manager.v1"
    assert im.AUDIT_SCHEMA == "audit.ndjson/1"
    kinds = {im.KIND_CREATED, im.KIND_DROPPED, im.KIND_BOUND, im.KIND_UNBOUND, im.KIND_REJECTED}
    assert kinds.issubset(im._KINDS)


def test_stdlib_only():
    tree = ast.parse(open(im.__file__).read())
    allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__",
               "canonical_json", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_create_roundtrip_and_verify():
    mgr = IndexManager()
    rec = mgr.create("by-email", "users", "email", 1)
    assert rec.verify()
    assert rec.index_id == "by-email" and rec.table_id == "users"
    assert rec.field == "email" and rec.kind == im.KIND_BTREE
    assert mgr.index_ids() == ("by-email",)
    assert mgr.active_ids() == ("by-email",)
    stored = mgr.index_record("by-email")
    assert stored is not None and stored.digest == rec.digest
    assert mgr.index_record("nope") is None


def test_create_bad_inputs_fail_closed_and_burn_seq():
    mgr = IndexManager()
    bad = [
        ("", "t", "f"), ("  ", "t", "f"), (123, "t", "f"), (None, "t", "f"),
        ("idx", "", "f"), ("idx", "t", ""), ("idx", "t" * 300, "f"),
    ]
    seq = 1
    for index_id, table_id, field in bad:
        with pytest.raises(im.IndexManagerError):
            mgr.create(index_id, table_id, field, seq)
        seq += 1
    with pytest.raises(im.BadKindError):
        mgr.create("k", "t", "f", seq, kind="gist")
    # every failed mutation consumed its seq: the next fresh seq must work
    rec = mgr.create("good", "t", "f", seq + 1, kind=im.KIND_HASH)
    assert rec.kind == im.KIND_HASH
    kinds = [e["kind"] for e in mgr.audit_log()]
    assert kinds.count(im.KIND_REJECTED) == len(bad) + 1


def test_duplicate_create_never_recycles():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    with pytest.raises(im.DuplicateIndexError):
        mgr.create("idx", "t", "other", 2)
    mgr.drop("idx", 3)
    with pytest.raises(im.DuplicateIndexError):
        mgr.create("idx", "t", "f", 4)


def test_drop_terminality():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    rec = mgr.drop("idx", 2)
    assert rec.verify()
    assert mgr.active_ids() == ()
    assert mgr.index_ids() == ("idx",)  # catalog keeps the entry, marked dropped
    with pytest.raises(im.DroppedIndexError):
        mgr.drop("idx", 3)
    with pytest.raises(im.UnknownIndexError):
        mgr.drop("ghost", 4)


def test_bind_unbind_lifecycle():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    b1 = mgr.bind("idx", "a@x.com", "row-1", 2)
    b2 = mgr.bind("idx", "a@x.com", "row-2", 3)
    assert b1.verify() and b2.verify()
    assert b1.key_digest == b2.key_digest  # same key pins identically
    assert mgr.binding_count("idx") == 2
    with pytest.raises(im.DuplicateBindingError):
        mgr.bind("idx", "a@x.com", "row-1", 4)
    u = mgr.unbind("idx", "a@x.com", "row-1", 5)
    assert u.verify()
    assert mgr.binding_count("idx") == 1
    with pytest.raises(im.UnknownBindingError):
        mgr.unbind("idx", "a@x.com", "row-1", 6)
    with pytest.raises(im.UnknownIndexError):
        mgr.bind("ghost", "k", "r", 7)
    with pytest.raises(im.DroppedIndexError):
        mgr.create("d", "t", "f", 8)
        mgr.drop("d", 9)
        mgr.bind("d", "k", "r", 10)


def test_key_validation():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    seq = 2
    for bad in (True, False, 1.5, None, b"x", ["k"], 2**54, ""):
        with pytest.raises(im.BadKeyError):
            mgr.bind("idx", bad, "row", seq)
        seq += 1
    for i, good in enumerate((0, -5, 42, "name", "a@b.c")):
        rec = mgr.bind("idx", good, f"row-good-{i}", seq)
        assert rec.verify()
        seq += 1
    with pytest.raises(im.BadRowError):
        mgr.bind("idx", "k", "", seq)


def test_lookup_is_pure_read_view():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    mgr.bind("idx", "a@x.com", "row-2", 2)
    mgr.bind("idx", "a@x.com", "row-1", 3)
    mgr.bind("idx", "b@x.com", "row-3", 4)
    r1 = mgr.lookup("idx", "a@x.com", 5)
    assert r1.verify()
    assert r1.row_ids == ("row-1", "row-2")  # sorted, deterministic
    # pure read: same seq twice must not advance the ledger
    r2 = mgr.lookup("idx", "a@x.com", 5)
    assert r2.row_ids == r1.row_ids
    empty = mgr.lookup("idx", "missing@x.com", 6)
    assert empty.row_ids == ()
    with pytest.raises(im.UnknownIndexError):
        mgr.lookup("ghost", "k", 7)
    before = len(mgr.audit_log())
    mgr.lookup("idx", "a@x.com", 9)  # fresh seq allowed
    assert len(mgr.audit_log()) == before  # but writes no audit row


def test_keys_view_sorted_digests():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    mgr.bind("idx", "k1", "r1", 2)
    mgr.bind("idx", "k2", "r2", 3)
    report = mgr.keys("idx", 4)
    assert report.count == 2
    assert report.key_digests == tuple(sorted(report.key_digests))
    assert all(d.startswith("sha256:") for d in report.key_digests)
    with pytest.raises(im.UnknownIndexError):
        mgr.keys("ghost", 5)


def test_seq_strictly_increasing():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    with pytest.raises(im.SeqOrderError):
        mgr.create("idx2", "t", "f", 1)  # rewind
    with pytest.raises(im.SeqOrderError):
        mgr.bind("idx", "k", "r", True)  # bool refused
    with pytest.raises(im.SeqOrderError):
        mgr.bind("idx", "k", "r", "2")  # str refused
    with pytest.raises(im.SeqOrderError):
        mgr.drop("idx", 0)  # non-positive is not fresh
    mgr.create("idx2", "t", "f", 2)  # fresh seq works


def test_audit_shapes_and_banned_keys():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    mgr.bind("idx", "secret-key", "row-1", 2)
    mgr.drop("idx", 3)
    log = mgr.audit_log()
    assert [e["kind"] for e in log] == [
        im.KIND_CREATED, im.KIND_BOUND, im.KIND_DROPPED,
    ]
    for e in log:
        assert e["schema"] == im.AUDIT_SCHEMA
        assert "key" not in e["detail"] and "keys" not in e["detail"]
        assert "secret-key" not in str(e)  # raw keys banned from the boundary
        assert "digest" in e
    with pytest.raises(im.AuditKindError):
        im.index_manager_audit_event("bogus-kind", 4)
    with pytest.raises(im.AuditKindError):
        im.index_manager_audit_event(im.KIND_CREATED, 4, key="leak")


def test_mixed_key_types_stay_distinct():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    mgr.bind("idx", 1, "row-int", 2)
    mgr.bind("idx", "1", "row-str", 3)
    assert mgr.lookup("idx", 1, 4).row_ids == ("row-int",)
    assert mgr.lookup("idx", "1", 5).row_ids == ("row-str",)
    assert mgr.keys("idx", 6).count == 2


def test_rejected_rows_booked():
    mgr = IndexManager()
    mgr.create("idx", "t", "f", 1)
    with pytest.raises(im.DuplicateIndexError):
        mgr.create("idx", "t", "f", 2)
    with pytest.raises(im.UnknownBindingError):
        mgr.unbind("idx", "k", "r", 3)
    rejected = [e for e in mgr.audit_log() if e["kind"] == im.KIND_REJECTED]
    assert len(rejected) == 2
    assert {e["detail"]["error"] for e in rejected} == {
        "DuplicateIndexError", "UnknownBindingError",
    }


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, im.__file__], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert "index-manager OK" in proc.stdout
