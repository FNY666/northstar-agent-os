"""Tests for key_value_store (15 tests)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from key_value_store import (
    SCHEMA_PIN,
    KEY_VALUE_STORE_VERSION,
    AuditKindError,
    BadColumnFamilyError,
    BadKeyError,
    BadScanError,
    BadValueError,
    ColumnFamilyRecord,
    DeleteRecord,
    GetOutcome,
    KeyValueStore,
    KeyValueStoreError,
    PutRecord,
    ScanReport,
    SeqOrderError,
    key_value_store_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "key_value_store.py"


def test_version_and_schema_pins():
    assert KEY_VALUE_STORE_VERSION == "key-value-store.v1"
    assert SCHEMA_PIN == "northstar.key-value-store.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {"hashlib", "math", "threading", "dataclasses", "typing",
               "__future__", "canonical_json", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_put_roundtrip():
    kv = KeyValueStore("kv")
    rec = kv.put("default", "k1", "v1", seq=1)
    assert isinstance(rec, PutRecord)
    assert not rec.overwritten
    assert rec.key_digest.startswith("sha256:")
    assert rec.value_digest.startswith("sha256:")
    d = rec.as_dict()
    assert d["schema"] == SCHEMA_PIN and d["version"] == KEY_VALUE_STORE_VERSION


def test_put_overwrite_flag():
    kv = KeyValueStore("kv")
    kv.put("default", "k1", "v1", seq=1)
    rec = kv.put("default", "k1", "v2", seq=2)
    assert rec.overwritten
    assert kv.get("default", "k1", seq=3).value == "v2"


def test_get_miss_is_data_not_raised():
    kv = KeyValueStore("kv")
    out = kv.get("default", "ghost", seq=1)
    assert isinstance(out, GetOutcome)
    assert not out.found and out.value is None
    assert kv.stats()["misses"] == 1 and kv.stats()["hits"] == 0


def test_delete_lifecycle():
    kv = KeyValueStore("kv")
    kv.put("default", "k1", "v1", seq=1)
    rec = kv.delete("default", "k1", seq=2)
    assert isinstance(rec, DeleteRecord)
    assert rec.existed
    assert not kv.get("default", "k1", seq=3).found


def test_delete_missing_is_data():
    kv = KeyValueStore("kv")
    rec = kv.delete("default", "never-there", seq=1)
    assert not rec.existed  # RocksDB delete is a valid no-op


def test_scan_range_and_order():
    kv = KeyValueStore("kv")
    for k, v in (("c", 3), ("a", 1), ("b", 2), ("d", 4)):
        kv.put("default", k, v, seq=len(kv.audit_log()) + 1)
    rep = kv.scan("default", seq=5, start="a", end="c")
    assert isinstance(rep, ScanReport)
    assert [k for k, _ in rep.entries] == ["a", "b"]  # half-open, key order
    rep_all = kv.scan("default", seq=6)
    assert [k for k, _ in rep_all.entries] == ["a", "b", "c", "d"]


def test_scan_limit():
    kv = KeyValueStore("kv")
    for i in range(5):
        kv.put("default", f"k{i}", i, seq=i + 1)
    rep = kv.scan("default", seq=6, limit=2)
    assert len(rep.entries) == 2
    assert [k for k, _ in rep.entries] == ["k0", "k1"]


def test_scan_start_gte_end_refused():
    kv = KeyValueStore("kv")
    with pytest.raises(BadScanError):
        kv.scan("default", seq=1, start="z", end="a")


def test_column_family_isolation():
    kv = KeyValueStore("kv")
    kv.column_family("meta", seq=1)
    kv.put("default", "k", "v-default", seq=2)
    kv.put("meta", "k", "v-meta", seq=3)
    assert kv.get("default", "k", seq=4).value == "v-default"
    assert kv.get("meta", "k", seq=5).value == "v-meta"


def test_unknown_column_family_refused():
    kv = KeyValueStore("kv")
    with pytest.raises(BadColumnFamilyError):
        kv.get("nope", "k", seq=1)


def test_bad_inputs_burn_seq_and_audit_rejection():
    kv = KeyValueStore("kv")
    bad = [
        ("put", ("default", "", "v")),
        ("put", ("default", "k", None)),
        ("put", ("default", "k", float("nan"))),
        ("put", ("default", "k", 2**54)),
        ("get", ("default", "")),
        ("scan", ("default",), {"limit": 0}),
    ]
    seq = 1
    for op, args, *rest in bad:
        kwargs = rest[0] if rest else {}
        with pytest.raises(KeyValueStoreError):
            getattr(kv, op)(*args, seq=seq, **kwargs)
        seq += 1
    # Every failed mutation consumed its seq; the next fresh seq must work.
    kv.put("default", "ok", "v", seq=seq)
    rejected = [r for r in kv.audit_log() if r["kind"] == "key-value-store.rejected"]
    assert len(rejected) == len(bad)


def test_seq_ordering():
    kv = KeyValueStore("kv")
    kv.put("default", "k", "v", seq=2)
    with pytest.raises(SeqOrderError):
        kv.put("default", "k", "v", seq=2)  # not strictly increasing
    with pytest.raises(SeqOrderError):
        kv.put("default", "k", "v", seq=True)
    with pytest.raises(SeqOrderError):
        kv.put("default", "k", "v", seq="3")


def test_audit_shapes_and_leak_ban():
    rows = key_value_store_audit_event("put", 1, key_digest="sha256:x").items()
    rec = dict(rows)
    assert rec["schema"] == "audit.ndjson/1"
    assert rec["kind"] == "key-value-store.put"
    with pytest.raises(AuditKindError):
        key_value_store_audit_event("put", 1, value="secret")
    with pytest.raises(AuditKindError):
        key_value_store_audit_event("nope", 1)
    kv = KeyValueStore("kv")
    kv.put("default", "k", "v", seq=1)
    kinds = {r["kind"] for r in kv.audit_log()}
    assert "key-value-store.put" in kinds
    for r in kv.audit_log():
        assert "value" not in r and "raw" not in r and "payload" not in r


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert "key-value-store OK" in proc.stdout
