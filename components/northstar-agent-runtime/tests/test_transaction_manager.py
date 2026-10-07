"""Tests for the transaction_manager lifecycle ledger (15 tests)."""

import ast
import os
import subprocess
import sys

import pytest

import transaction_manager
from transaction_manager import (
    SCHEMA_PIN,
    TRANSACTION_MANAGER_VERSION,
    AuditKindError,
    BadIsolationError,
    BadReasonError,
    BadTxnError,
    DuplicateTxnError,
    RetiredTxnError,
    SeqOrderError,
    TerminalTxnError,
    TransactionManager,
    UnknownTxnError,
    transaction_manager_audit_event,
)


def test_version_and_schema_pins():
    assert TRANSACTION_MANAGER_VERSION == "transaction-manager.v1"
    assert SCHEMA_PIN == "northstar.transaction-manager.v1"


def test_stdlib_only():
    src = open(transaction_manager.__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    allowed = {
        "hashlib", "json", "threading", "dataclasses", "typing", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module in allowed, node.module


def test_begin_commit_roundtrip():
    mgr = TransactionManager()
    rec = mgr.begin("txn-1", 1)
    assert rec.txn_id == "txn-1"
    assert rec.isolation == "read-committed"
    assert rec.seq == 1
    assert rec.verify()
    crec = mgr.commit("txn-1", 2)
    assert crec.verify()
    assert mgr.status("txn-1", 3) == "committed"


def test_begin_rollback_roundtrip():
    mgr = TransactionManager()
    mgr.begin("txn-2", 1, isolation="serializable")
    rrec = mgr.rollback("txn-2", 2, reason="conflict")
    assert rrec.reason == "conflict"
    assert rrec.verify()
    assert mgr.status("txn-2", 3) == "rolled-back"
    assert mgr.isolation_of("txn-2", 4) == "serializable"


def test_bad_txn_ids():
    mgr = TransactionManager()
    bad_ids = ["", "   ", "a b", "x" * 257, 123, None, b"bytes"]
    for i, bad in enumerate(bad_ids):
        with pytest.raises(BadTxnError):
            mgr.begin(bad, 10 + i)
    # every failed mutation consumed its seq
    assert mgr.stats(100)["seq"] == 10 + len(bad_ids) - 1


def test_duplicate_begin_refused():
    mgr = TransactionManager()
    mgr.begin("txn-d", 1)
    with pytest.raises(DuplicateTxnError):
        mgr.begin("txn-d", 2)
    assert mgr.status("txn-d", 3) == "active"
    rows = mgr.audit_log()
    assert rows[-1]["kind"] == "rejected"


def test_retired_id_never_recycled():
    mgr = TransactionManager()
    mgr.begin("txn-r", 1)
    mgr.commit("txn-r", 2)
    with pytest.raises(RetiredTxnError):
        mgr.begin("txn-r", 3)
    mgr.begin("txn-s", 4)
    mgr.rollback("txn-s", 5)
    with pytest.raises(RetiredTxnError):
        mgr.begin("txn-s", 6)


def test_commit_unknown_and_terminal():
    mgr = TransactionManager()
    with pytest.raises(UnknownTxnError):
        mgr.commit("ghost", 1)
    mgr.begin("txn-t", 2)
    mgr.commit("txn-t", 3)
    with pytest.raises(TerminalTxnError):
        mgr.commit("txn-t", 4)
    with pytest.raises(TerminalTxnError):
        mgr.rollback("txn-t", 5)


def test_rollback_unknown_and_terminal():
    mgr = TransactionManager()
    with pytest.raises(UnknownTxnError):
        mgr.rollback("ghost", 1)
    mgr.begin("txn-u", 2)
    mgr.rollback("txn-u", 3)
    with pytest.raises(TerminalTxnError):
        mgr.rollback("txn-u", 4)
    with pytest.raises(TerminalTxnError):
        mgr.commit("txn-u", 5)


def test_isolation_and_reason_vocab():
    mgr = TransactionManager()
    for i, level in enumerate(("read-committed", "repeatable-read", "serializable")):
        rec = mgr.begin(f"txn-i{i}", 1 + i * 10, isolation=level)
        assert rec.isolation == level
    with pytest.raises(BadIsolationError):
        mgr.begin("txn-bad", 100, isolation="snapshot")
    with pytest.raises(BadIsolationError):
        mgr.begin("txn-bad2", 101, isolation=123)
    for i, reason in enumerate(("explicit", "conflict", "timeout", "aborted")):
        mgr.begin(f"txn-r{i}", 200 + i * 10)
        rrec = mgr.rollback(f"txn-r{i}", 201 + i * 10, reason=reason)
        assert rrec.reason == reason
    mgr.begin("txn-br", 300)
    with pytest.raises(BadReasonError):
        mgr.rollback("txn-br", 301, reason="because")


def test_seq_ordering():
    mgr = TransactionManager()
    mgr.begin("txn-q", 5)
    with pytest.raises(SeqOrderError):
        mgr.commit("txn-q", 5)          # rewind: not strictly increasing
    with pytest.raises(SeqOrderError):
        mgr.commit("txn-q", True)       # bool is not an int
    with pytest.raises(SeqOrderError):
        mgr.commit("txn-q", "6")        # str is not an int
    with pytest.raises(SeqOrderError):
        mgr.commit("txn-q", -1)         # negative
    # failed seq claims did not advance the ledger
    assert mgr.stats(6)["seq"] == 5
    mgr.commit("txn-q", 6)              # works once seq advances


def test_audit_shapes_and_banned_keys():
    mgr = TransactionManager()
    mgr.begin("txn-a", 1)
    mgr.commit("txn-a", 2)
    rows = mgr.audit_log()
    assert [r["kind"] for r in rows] == ["txn-begun", "txn-committed"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == TRANSACTION_MANAGER_VERSION
        detail = row["detail"]
        assert not ({"payload", "payload_bytes", "value", "raw"} & set(detail))
    with pytest.raises(AuditKindError):
        transaction_manager_audit_event("bogus", {}, 1)
    with pytest.raises(AuditKindError):
        transaction_manager_audit_event("txn-begun", {"payload": b"x"}, 1)


def test_views_are_pure():
    mgr = TransactionManager()
    mgr.begin("txn-v1", 1)
    mgr.begin("txn-v2", 2)
    assert mgr.active_txn_ids() == ("txn-v1", "txn-v2")
    mgr.commit("txn-v1", 3)
    assert mgr.active_txn_ids() == ("txn-v2",)
    stats = mgr.stats(4)
    assert stats == {
        "active": 1, "committed": 1, "rolled_back": 0, "total": 2, "seq": 3,
    }
    # views validate seq shape but consume nothing and are rewind-safe
    assert mgr.stats(1)["seq"] == 3
    assert mgr.stats(2)["seq"] == 3  # rewind allowed on pure views
    with pytest.raises(SeqOrderError):
        mgr.stats("x")  # shape still validated


def test_frozen_records():
    mgr = TransactionManager()
    rec = mgr.begin("txn-f", 1)
    with pytest.raises(Exception):
        rec.txn_id = "mutated"  # frozen dataclass


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(transaction_manager.__file__),
                                      "transaction_manager.py")],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "transaction-manager OK" in proc.stdout
