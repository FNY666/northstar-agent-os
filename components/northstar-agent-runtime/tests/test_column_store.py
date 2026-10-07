"""Tests for column_store.py (Cassandra-shaped wide-column ledger)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import column_store
from column_store import (
    AuditKindError,
    BadColumnError,
    BadKeyError,
    BadTableError,
    BadValueError,
    ColumnStore,
    DuplicateTableError,
    SeqOrderError,
    UnknownTableError,
    column_store_audit_event,
)


def _fresh() -> ColumnStore:
    return ColumnStore()


def test_version_and_schema_pins() -> None:
    assert column_store.COLUMN_STORE_VERSION == "column-store.v1"
    assert column_store.SCHEMA_PIN == "northstar.column-store.v1"
    assert column_store.AUDIT_SCHEMA == "northstar.audit.ndjson/1"
    assert set(column_store._AUDIT_KINDS) == {
        "table-created",
        "inserted",
        "deleted",
        "rejected",
    }


def test_stdlib_only() -> None:
    column_store._stdlib_only(column_store.__file__)


def test_create_table_roundtrip() -> None:
    store = _fresh()
    rec = store.create_table("users", 1)
    assert rec.table_id == "users"
    assert rec.seq == 1
    assert rec.record_digest.startswith("sha256:")
    assert store.table("users") == rec
    assert store.table_ids() == ("users",)
    d = rec.as_dict()
    assert d["schema"] == "northstar.column-store.v1"


def test_create_table_bad_inputs() -> None:
    store = _fresh()
    s = 0
    for bad in ("", "has space", "x" * 257, 123, None, True):
        s += 1
        with pytest.raises((BadTableError,)):
            store.create_table(bad, s)
    # duplicate refused, seq consumed
    s += 1
    store.create_table("t", s)
    s += 1
    with pytest.raises(DuplicateTableError):
        store.create_table("t", s)
    with pytest.raises(SeqOrderError):
        store.create_table("t2", s)  # rewind: seq already consumed


def test_insert_select_roundtrip() -> None:
    store = _fresh()
    store.create_table("users", 1)
    rec = store.insert("users", "u1", {"name": "ada", "age": 36}, 2)
    assert rec.columns == ("age", "name")
    assert rec.ts == 2
    assert rec.record_digest.startswith("sha256:")
    got = store.select("users", "u1", 3)
    assert got.found
    by_col = {c.column: c.value for c in got.cells}
    assert by_col == {"name": "ada", "age": 36}
    assert got.result_digest.startswith("sha256:")
    # column projection
    proj = store.select("users", "u1", 4, columns=("name",))
    assert [c.column for c in proj.cells] == ["name"]


def test_insert_upsert_last_write_wins() -> None:
    store = _fresh()
    store.create_table("t", 1)
    store.insert("t", "k", {"a": 1, "b": 2}, 2)
    store.insert("t", "k", {"a": 9}, 3)  # newer ts wins for "a" only
    got = store.select("t", "k", 4)
    by_col = {c.column: c.value for c in got.cells}
    assert by_col == {"a": 9, "b": 2}
    assert store.select("t", "missing", 5).found is False


def test_insert_bad_inputs() -> None:
    store = _fresh()
    store.create_table("t", 1)
    s = 1
    with pytest.raises(UnknownTableError):
        s += 1
        store.insert("nope", "k", {"a": 1}, s)
    for bad_key in ("", 123, None):
        s += 1
        with pytest.raises(BadKeyError):
            store.insert("t", bad_key, {"a": 1}, s)
    for bad_vals in ({}, {"a b": 1}, {"": 1}):
        s += 1
        with pytest.raises((BadColumnError, BadValueError)):
            store.insert("t", "k", bad_vals, s)
    # non-canonicalizable values rejected fail-closed
    for bad in (float("nan"), float("inf"), 2**53, object(), {1: "x"}):
        s += 1
        with pytest.raises(BadValueError):
            store.insert("t", "k", {"v": bad}, s)


def test_delete_column_tombstone_hides_cell() -> None:
    store = _fresh()
    store.create_table("t", 1)
    store.insert("t", "k", {"a": 1, "b": 2}, 2)
    rec = store.delete("t", "k", 3, columns=("a",))
    assert rec.scope == "columns"
    assert rec.columns == ("a",)
    got = store.select("t", "k", 4)
    assert got.found and [c.column for c in got.cells] == ["b"]
    # tombstone does not block a newer write
    store.insert("t", "k", {"a": 5}, 5)
    got = store.select("t", "k", 6)
    assert {c.column: c.value for c in got.cells} == {"a": 5, "b": 2}


def test_delete_row_tombstone_hides_row() -> None:
    store = _fresh()
    store.create_table("t", 1)
    store.insert("t", "k", {"a": 1}, 2)
    rec = store.delete("t", "k", 3)
    assert rec.scope == "row"
    assert store.select("t", "k", 4).found is False
    # a newer insert resurrects the row (Cassandra LWW over tombstone)
    store.insert("t", "k", {"a": 2}, 5)
    got = store.select("t", "k", 6)
    assert got.found and got.cells[0].value == 2


def test_delete_bad_inputs() -> None:
    store = _fresh()
    store.create_table("t", 1)
    s = 1
    with pytest.raises(UnknownTableError):
        s += 1
        store.delete("nope", "k", s)
    with pytest.raises(BadColumnError):
        s += 1
        store.delete("t", "k", s, columns=())
    with pytest.raises(BadColumnError):
        s += 1
        store.delete("t", "k", s, columns="a")  # not a tuple/list


def test_select_bad_inputs() -> None:
    store = _fresh()
    store.create_table("t", 1)
    with pytest.raises(UnknownTableError):
        store.select("nope", "k", 2)
    with pytest.raises(BadKeyError):
        store.select("t", "", 2)
    with pytest.raises(BadColumnError):
        store.select("t", "k", 2, columns=("bad col",))
    # reads are pure: seq shape validated but not consumed
    store.select("t", "k", 2)
    store.select("t", "k", 2)  # same seq twice is fine
    with pytest.raises(SeqOrderError):
        store.select("t", "k", "x")


def test_seq_ordering_and_failed_mutation_consumes_seq() -> None:
    store = _fresh()
    with pytest.raises(SeqOrderError):
        store.create_table("t", -1)
    with pytest.raises(SeqOrderError):
        store.create_table("t", True)
    with pytest.raises(SeqOrderError):
        store.create_table("t", 1.5)
    store.create_table("t", 1)
    # failed mutation consumes its seq: next fresh seq must be 3
    with pytest.raises(DuplicateTableError):
        store.create_table("t", 2)
    with pytest.raises(SeqOrderError):
        store.insert("t", "k", {"a": 1}, 2)  # rewind
    store.insert("t", "k", {"a": 1}, 3)
    # rejected rows are audited
    kinds = [e["event"] for e in store.audit_log()]
    assert "column-store.rejected" in kinds


def test_audit_shapes_and_value_leak_ban() -> None:
    store = _fresh()
    store.create_table("users", 1)
    store.insert("users", "u1", {"secret": "hunter2"}, 2)
    store.delete("users", "u1", 3, columns=("secret",))
    for event in store.audit_log():
        assert event["schema"] == "northstar.audit.ndjson/1"
        assert event["module"] == "column-store.v1"
        for banned in ("value", "values", "cells", "payload", "raw", "body", "data"):
            assert banned not in event, f"leak: {banned}"
    kinds = {e["event"] for e in store.audit_log()}
    assert kinds == {
        "column-store.table-created",
        "column-store.inserted",
        "column-store.deleted",
    }
    # builder rejects unknown kinds and banned detail keys
    with pytest.raises(AuditKindError):
        column_store_audit_event("nope", 9)
    with pytest.raises(AuditKindError):
        column_store_audit_event("inserted", 9, value="x")


def test_views_and_stats() -> None:
    store = _fresh()
    store.create_table("t1", 1)
    store.create_table("t2", 2)
    store.insert("t1", "k1", {"a": 1}, 3)
    store.insert("t1", "k2", {"a": 2}, 4)
    store.delete("t1", "k1", 5, columns=("a",))
    assert store.table_ids() == ("t1", "t2")
    assert store.keys("t1") == ("k1", "k2")
    stats = store.stats(6)
    assert stats["tables"] == 2
    assert stats["cells"] == 2
    assert stats["tombstones"] == 1
    assert stats["audit_rows"] == 5
    assert stats["schema"] == "northstar.column-store.v1"
    assert store.table("missing") is None
    with pytest.raises(UnknownTableError):
        store.keys("missing")
    # cross-instance digest determinism: identical writes, identical digests
    other = _fresh()
    other.create_table("t1", 1)
    other.insert("t1", "k2", {"a": 2}, 2)
    r1 = store.select("t1", "k2", 7)
    r2 = other.select("t1", "k2", 3)
    assert r1.result_digest == r2.result_digest


def test_main_self_check() -> None:
    proc = subprocess.run(
        [sys.executable, column_store.__file__],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "column-store OK" in proc.stdout
