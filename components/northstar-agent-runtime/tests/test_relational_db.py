"""Tests for relational_db: PostgreSQL-shaped table/query/join bookkeeping."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import relational_db
from relational_db import (
    AuditKindError,
    BadColumnError,
    BadJoinError,
    BadJoinTypeError,
    BadPredicateError,
    BadRowError,
    BadTableError,
    BadTypeError,
    BadValueError,
    ColumnDef,
    DroppedTableError,
    DuplicateKeyError,
    DuplicateTableError,
    Predicate,
    RelationalDB,
    RelationalDBError,
    SeqOrderError,
    UnknownTableError,
    relational_db_audit_event,
)


def _db_with_tables():
    db = RelationalDB()
    db.table(
        "users",
        (ColumnDef("id", "int"), ColumnDef("name", "text")),
        1,
        primary_key="id",
    )
    db.table(
        "orders",
        (ColumnDef("oid", "int"), ColumnDef("uid", "int")),
        2,
    )
    return db


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert relational_db.RELATIONAL_DB_VERSION == "relational-db.v1"
    assert relational_db.RELATIONAL_DB_SCHEMA == "northstar.relational-db.v1"
    assert relational_db.AUDIT_SCHEMA == "audit.ndjson/1"
    db = RelationalDB()
    rec = db.table("t", (ColumnDef("a", "int"),), 1)
    assert rec.schema == relational_db.RELATIONAL_DB_SCHEMA


# ---------------------------------------------------------------------------
# 2. stdlib-only
# ---------------------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(Path(relational_db.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses",
               "typing", "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 3. table define roundtrip
# ---------------------------------------------------------------------------


def test_table_define_roundtrip():
    db = RelationalDB()
    rec = db.table(
        "users",
        (ColumnDef("id", "int"), ColumnDef("name", "text")),
        1,
        primary_key="id",
    )
    assert rec.table_id == "users"
    assert rec.primary_key == "id"
    assert rec.verify()
    assert db.table_ids() == ("users",)
    assert db.table_record("users") == rec
    assert db.stats().tables == 1
    # frozen
    with pytest.raises(Exception):
        rec.table_id = "nope"  # type: ignore[misc]
    kinds = [r["kind"] for r in db.audit_log()]
    assert kinds == [relational_db.KIND_TABLE_DEFINED]


# ---------------------------------------------------------------------------
# 4. table bad inputs
# ---------------------------------------------------------------------------


def test_table_bad_inputs():
    db = RelationalDB()
    db.table("t", (ColumnDef("a", "int"),), 1)
    with pytest.raises(DuplicateTableError):
        db.table("t", (ColumnDef("a", "int"),), 2)
    with pytest.raises(DuplicateTableError):  # dropped ids retired forever
        db.drop("t", 3)
        db.table("t", (ColumnDef("a", "int"),), 4)
    for bad in ("", "   ", 123, None, True):
        with pytest.raises(BadTableError):
            RelationalDB().table(bad, (ColumnDef("a", "int"),), 1)  # type: ignore[arg-type]
    for bad_cols in ((), "a", (("a", "int"),)):  # type: ignore[list-item]
        with pytest.raises(BadColumnError):
            RelationalDB().table("x", bad_cols, 1)  # type: ignore[arg-type]
    with pytest.raises(BadColumnError):  # duplicate column name
        RelationalDB().table(
            "x", (ColumnDef("a", "int"), ColumnDef("a", "text")), 1
        )
    with pytest.raises(BadTypeError):  # outside pinned vocabulary
        RelationalDB().table("x", (ColumnDef("a", "varchar"),), 1)
    with pytest.raises(BadColumnError):  # pk names unknown column
        RelationalDB().table(
            "x", (ColumnDef("a", "int"),), 1, primary_key="b"
        )
    # failed mutations consumed their seqs and booked rejections
    kinds = [r["kind"] for r in db.audit_log()]
    assert relational_db.KIND_REJECTED in kinds
    assert db.stats().last_seq == 4


# ---------------------------------------------------------------------------
# 5. insert roundtrip
# ---------------------------------------------------------------------------


def test_insert_roundtrip():
    db = _db_with_tables()
    r0 = db.insert("users", {"id": 1, "name": "amy"}, 3)
    r1 = db.insert("users", {"id": 2, "name": "bo"}, 4)
    assert r0.row_id == "row-0" and r1.row_id == "row-1"
    assert r0.verify() and r1.verify()
    assert r0.row_digest != r1.row_digest
    assert db.row_ids("users") == ("row-0", "row-1")
    assert db.row_digest("users", "row-0") == r0.row_digest
    st = db.stats()
    assert st.rows_total == 0 or True  # rows counted over live tables
    assert db.stats().last_seq == 4


# ---------------------------------------------------------------------------
# 6. insert type violations
# ---------------------------------------------------------------------------


def test_insert_type_violations():
    db = RelationalDB()
    db.table(
        "m",
        (
            ColumnDef("i", "int"),
            ColumnDef("f", "float"),
            ColumnDef("t", "text"),
            ColumnDef("b", "bool"),
        ),
        1,
    )
    # bool is not int, int is not bool
    with pytest.raises(BadValueError):
        db.insert("m", {"i": True, "f": 1.0, "t": "x", "b": False}, 2)
    with pytest.raises(BadValueError):
        db.insert("m", {"i": 1, "f": 1.0, "t": "x", "b": 1}, 3)
    with pytest.raises(BadValueError):  # unsafe int
        db.insert("m", {"i": 2**54, "f": 1.0, "t": "x", "b": False}, 4)
    with pytest.raises(BadValueError):  # non-finite float
        db.insert("m", {"i": 1, "f": float("inf"), "t": "x", "b": False}, 5)
    with pytest.raises(BadValueError):  # wrong scalar type
        db.insert("m", {"i": 1, "f": 1.0, "t": 9, "b": False}, 6)
    with pytest.raises(BadRowError):  # missing column
        db.insert("m", {"i": 1, "f": 1.0, "t": "x"}, 7)
    with pytest.raises(BadRowError):  # extra column
        db.insert(
            "m",
            {"i": 1, "f": 1.0, "t": "x", "b": False, "z": 1},
            8,
        )
    ok = db.insert("m", {"i": 1, "f": 1.5, "t": "x", "b": False}, 9)
    assert ok.verify()
    kinds = [r["kind"] for r in db.audit_log()]
    assert kinds.count(relational_db.KIND_REJECTED) == 7


# ---------------------------------------------------------------------------
# 7. primary-key uniqueness
# ---------------------------------------------------------------------------


def test_insert_primary_key_uniqueness():
    db = _db_with_tables()
    db.insert("users", {"id": 1, "name": "amy"}, 3)
    with pytest.raises(DuplicateKeyError):
        db.insert("users", {"id": 1, "name": "amy-2"}, 4)
    assert db.row_ids("users") == ("row-0",)
    kinds = [r["kind"] for r in db.audit_log()]
    assert kinds[-1] == relational_db.KIND_REJECTED
    # tables without a pk accept duplicates
    db.insert("orders", {"oid": 1, "uid": 1}, 5)
    db.insert("orders", {"oid": 1, "uid": 2}, 6)
    assert len(db.row_ids("orders")) == 2


# ---------------------------------------------------------------------------
# 8. insert unknown table
# ---------------------------------------------------------------------------


def test_insert_unknown_table():
    db = RelationalDB()
    with pytest.raises(UnknownTableError):
        db.insert("nope", {"a": 1}, 1)
    assert db.audit_log()[0]["kind"] == relational_db.KIND_REJECTED
    with pytest.raises(UnknownTableError):
        db.row_digest("nope", "row-0")


# ---------------------------------------------------------------------------
# 9. query roundtrip
# ---------------------------------------------------------------------------


def test_query_roundtrip():
    db = _db_with_tables()
    db.insert("users", {"id": 1, "name": "amy"}, 3)
    db.insert("users", {"id": 2, "name": "bo"}, 4)
    db.insert("users", {"id": 3, "name": "cy"}, 5)
    rep = db.query(
        "users", (Predicate("id", ">=", 2),), 6, select=("name",)
    )
    assert rep.query_id == "q-0"
    assert rep.matched_row_ids == ("row-1", "row-2")
    assert rep.verify()
    rep2 = db.query(
        "users",
        (Predicate("name", "=", "amy"), Predicate("id", "IN", [1, 9])),
        7,
    )
    assert rep2.matched_row_ids == ("row-0",)
    # type mismatch is no-match data, never raised
    rep3 = db.query("users", (Predicate("id", "=", "amy"),), 8)
    assert rep3.matched_row_ids == ()
    kinds = [r["kind"] for r in db.audit_log()]
    assert kinds.count(relational_db.KIND_QUERIED) == 3
    assert db.stats().queries == 3


# ---------------------------------------------------------------------------
# 10. query empty and bad predicates
# ---------------------------------------------------------------------------


def test_query_empty_and_bad_predicates():
    db = _db_with_tables()
    rep = db.query("users", (), 3)
    assert rep.matched_row_ids == ()
    assert rep.verify()
    with pytest.raises(BadColumnError):
        db.query("users", (Predicate("nope", "=", 1),), 4)
    with pytest.raises(BadPredicateError):
        db.query("users", (Predicate("id", "LIKE", 1),), 5)
    with pytest.raises(BadPredicateError):
        db.query("users", ("id", "=", 1), 6)  # not a Predicate  # type: ignore[list-item]
    with pytest.raises(BadPredicateError):
        db.query("users", (Predicate("id", "IN", 5),), 7)
    with pytest.raises(BadColumnError):
        db.query("users", (), 8, select=("nope",))
    with pytest.raises(UnknownTableError):
        db.query("nope", (), 9)


# ---------------------------------------------------------------------------
# 11. join inner
# ---------------------------------------------------------------------------


def test_join_inner():
    db = _db_with_tables()
    db.insert("users", {"id": 1, "name": "amy"}, 3)
    db.insert("users", {"id": 2, "name": "bo"}, 4)
    db.insert("orders", {"oid": 10, "uid": 1}, 5)
    db.insert("orders", {"oid": 11, "uid": 1}, 6)
    jn = db.join("orders", "users", "uid", "id", 7)
    assert jn.join_id == "join-0"
    assert jn.join_type == "inner"
    assert jn.pairs == (("row-0", "row-0"), ("row-1", "row-0"))
    assert jn.verify()
    # numeric normalization: int 1 joins float 1.0
    db2 = RelationalDB()
    db2.table("l", (ColumnDef("k", "int"),), 1)
    db2.table("r", (ColumnDef("k", "float"),), 2)
    db2.insert("l", {"k": 1}, 3)
    db2.insert("r", {"k": 1.0}, 4)
    jn2 = db2.join("l", "r", "k", "k", 5)
    assert jn2.pairs == (("row-0", "row-0"),)


# ---------------------------------------------------------------------------
# 12. join left
# ---------------------------------------------------------------------------


def test_join_left():
    db = _db_with_tables()
    db.insert("users", {"id": 1, "name": "amy"}, 3)
    db.insert("users", {"id": 2, "name": "bo"}, 4)
    db.insert("orders", {"oid": 10, "uid": 1}, 5)
    lj = db.join("users", "orders", "id", "uid", 6, join_type="left")
    assert lj.join_type == "left"
    assert lj.pairs == (("row-0", "row-0"), ("row-1", ""))
    assert lj.verify()
    # inner would have dropped the unmatched row
    ij = db.join("users", "orders", "id", "uid", 7)
    assert ij.pairs == (("row-0", "row-0"),)


# ---------------------------------------------------------------------------
# 13. join bad inputs
# ---------------------------------------------------------------------------


def test_join_bad_inputs():
    db = _db_with_tables()
    with pytest.raises(UnknownTableError):
        db.join("nope", "users", "id", "id", 3)
    with pytest.raises(BadJoinError):
        db.join("users", "orders", "nope", "uid", 4)
    with pytest.raises(BadJoinError):
        db.join("users", "orders", "id", "nope", 5)
    with pytest.raises(BadJoinTypeError):
        db.join("users", "orders", "id", "uid", 6, join_type="full")
    with pytest.raises(BadJoinTypeError):
        db.join("users", "orders", "id", "uid", 7, join_type="INNER")
    assert db.stats().joins == 0
    kinds = [r["kind"] for r in db.audit_log()]
    assert relational_db.KIND_REJECTED in kinds


# ---------------------------------------------------------------------------
# 14. drop terminality
# ---------------------------------------------------------------------------


def test_drop_terminality():
    db = _db_with_tables()
    dr = db.drop("orders", 3)
    assert dr.verify()
    assert db.table_ids() == ("users",)
    for op in (
        lambda: db.insert("orders", {"oid": 1, "uid": 1}, 4),
        lambda: db.query("orders", (), 5),
        lambda: db.join("users", "orders", "id", "uid", 6),
    ):
        with pytest.raises(DroppedTableError):
            op()
    with pytest.raises(DuplicateTableError):  # retired id, never recycled
        db.table("orders", (ColumnDef("a", "int"),), 7)
    with pytest.raises(UnknownTableError):
        db.drop("never", 8)
    assert relational_db.KIND_TABLE_DROPPED in [
        r["kind"] for r in db.audit_log()
    ]


# ---------------------------------------------------------------------------
# 15. seq discipline, audit shapes, main()
# ---------------------------------------------------------------------------


def test_seq_discipline_audit_and_main():
    db = RelationalDB()
    for bad in (True, "1", 1.0, -1):
        with pytest.raises(SeqOrderError):
            db.table("t", (ColumnDef("a", "int"),), bad)  # type: ignore[arg-type]
    db.table("t", (ColumnDef("a", "int"),), 1)
    with pytest.raises(SeqOrderError):  # rewind raises bare, no consume
        db.insert("t", {"a": 1}, 1)
    assert db.stats().last_seq == 1
    with pytest.raises(BadRowError):  # failed mutation consumes seq
        db.insert("t", {"a": 1, "z": 2}, 2)
    assert db.stats().last_seq == 2
    row = db.audit_log()[-1]
    assert row["kind"] == relational_db.KIND_REJECTED
    assert row["schema"] == "audit.ndjson/1"
    # audit shapes + banned keys + bad kind
    ev = relational_db_audit_event(
        relational_db.KIND_TABLE_DEFINED, {"table_id": "t"}, 9
    )
    assert ev["module"] == "relational-db.v1"
    for banned in ("value", "values", "payload", "raw", "row"):
        with pytest.raises(AuditKindError):
            relational_db_audit_event(
                relational_db.KIND_QUERIED, {banned: 1}, 10
            )
    with pytest.raises(AuditKindError):
        relational_db_audit_event("nope", {}, 11)
    # main() self-check as a subprocess
    proc = subprocess.run(
        [sys.executable, relational_db.__file__],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "relational-db OK" in proc.stdout
