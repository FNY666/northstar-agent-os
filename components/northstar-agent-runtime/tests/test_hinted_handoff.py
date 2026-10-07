"""Tests for hinted_handoff (Dynamo-style write buffering)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import hinted_handoff
from hinted_handoff import (
    HintedHandoff,
    ExpiredHintError,
    HintStateError,
    UnknownHintError,
    DuplicateHintError,
    BadHintError,
    BadNodeError,
    BadValueError,
    BadTTLSError,
    SeqOrderError,
    hinted_handoff_audit_event,
    HINTED_HANDOFF_VERSION,
    HINTED_HANDOFF_SCHEMA,
    KIND_STORED,
    KIND_DELIVERED,
    KIND_EXPIRED,
    KIND_REJECTED,
    STATUS_PENDING,
    STATUS_DELIVERED,
    STATUS_EXPIRED,
)


def test_version_and_schema_pins():
    assert HINTED_HANDOFF_VERSION == "hinted-handoff.v1"
    assert HINTED_HANDOFF_SCHEMA == "northstar.hinted-handoff.v1"


def test_stdlib_only():
    tree = ast.parse(Path(hinted_handoff.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0]
                if name == "canonical_json":
                    continue  # stdlib-first fallback
                assert name in allowed, name
        elif isinstance(node, ast.ImportFrom):
            if node.module == "canonical_json":
                continue  # stdlib-first fallback
            assert node.module in allowed, node.module


def test_store_roundtrip_and_record_shape():
    ledger = HintedHandoff()
    rec = ledger.store("h-1", "orders/42", "payload", "node-b", 1)
    assert rec.hint_id == "h-1"
    assert rec.key == "orders/42"
    assert rec.target_node == "node-b"
    assert rec.status == STATUS_PENDING
    assert rec.stored_seq == 1
    assert rec.expiry_seq == 101
    assert rec.value_type == "str"
    assert rec.value_digest.startswith("sha256:")
    assert rec.verify()
    assert ledger.hint("h-1") == rec
    assert ledger.hint_ids() == ("h-1",)


def test_store_duplicate_id_refused():
    ledger = HintedHandoff()
    ledger.store("h-1", "k", "v", "node-a", 1)
    with pytest.raises(DuplicateHintError):
        ledger.store("h-1", "k2", "v2", "node-b", 2)
    # Failed mutation consumed its seq: seq 2 is now taken.
    with pytest.raises(SeqOrderError):
        ledger.store("h-9", "k", "v", "node-a", 2)


def test_store_bad_inputs_fail_closed():
    ledger = HintedHandoff()
    cases = [
        ("", "k", "v", "n", 1),          # empty hint id
        (123, "k", "v", "n", 2),         # non-str hint id
        ("h-1", "", "v", "n", 3),        # empty key
        ("h-2", "k", "v", "", 4),        # empty node
        ("h-3", "k", float("nan"), "n", 5),  # NaN value
        ("h-4", "k", 2**54, "n", 6),     # unsafe int
        ("h-5", "k", "v", "n", 7, 0),    # zero TTL
        ("h-6", "k", "v", "n", 8, -3),   # negative TTL
        ("h-7", "k", "v", "n", 9, True),  # bool TTL
    ]
    seq = 0
    for case in cases:
        seq += 1
        hid, key, val, node, _ = case[:5]
        ttl = case[5] if len(case) > 5 else 100
        with pytest.raises(
            (BadHintError, BadNodeError, BadValueError, BadTTLSError)
        ):
            ledger.store(hid, key, val, node, seq, ttl_seqs=ttl)
    # One rejection audit row per refusal.
    kinds = [row["kind"] for row in ledger.audit_log()]
    assert kinds.count(KIND_REJECTED) == len(cases)


def test_deliver_lifecycle():
    ledger = HintedHandoff()
    ledger.store("h-1", "k", "v", "node-b", 1)
    rec = ledger.deliver("h-1", 2)
    assert rec.hint_id == "h-1"
    assert rec.target_node == "node-b"
    assert rec.stored_seq == 1
    assert rec.delivered_seq == 2
    assert rec.verify()
    assert ledger.hint("h-1").status == STATUS_DELIVERED
    assert ledger.pending() == ()
    with pytest.raises(HintStateError):
        ledger.deliver("h-1", 3)  # double delivery refused


def test_deliver_unknown_and_bad_seq():
    ledger = HintedHandoff()
    with pytest.raises(UnknownHintError):
        ledger.deliver("ghost", 1)
    with pytest.raises(SeqOrderError):
        ledger.deliver("ghost", -1)
    with pytest.raises(SeqOrderError):
        ledger.deliver("ghost", True)


def test_expire_sweep_and_views():
    ledger = HintedHandoff()
    ledger.store("h-1", "k", "v1", "node-a", 1, ttl_seqs=3)  # expiry 4
    ledger.store("h-2", "k", "v2", "node-a", 2, ttl_seqs=10)  # expiry 12
    report = ledger.expire(5)
    assert report.expired_ids == ("h-1",)
    assert report.expired_count == 1
    assert report.pending_count == 1
    assert report.verify()
    assert ledger.hint("h-1").status == STATUS_EXPIRED
    assert ledger.hint("h-2").status == STATUS_PENDING
    assert [r.hint_id for r in ledger.pending()] == ["h-2"]
    stats = ledger.stats()
    assert stats["total"] == 2
    assert stats["expired"] == 1
    assert stats["pending"] == 1
    assert stats["delivered"] == 0


def test_deliver_lapsed_but_unswept_refused():
    ledger = HintedHandoff()
    ledger.store("h-1", "k", "v", "node-a", 1, ttl_seqs=2)  # expiry 3
    with pytest.raises(ExpiredHintError):
        ledger.deliver("h-1", 3)
    with pytest.raises(ExpiredHintError):
        ledger.deliver("h-1", 9)
    # Still pending until a sweep books the transition.
    assert ledger.hint("h-1").status == STATUS_PENDING
    ledger.expire(10)
    assert ledger.hint("h-1").status == STATUS_EXPIRED


def test_seq_ordering_strict():
    ledger = HintedHandoff()
    ledger.store("h-1", "k", "v", "n", 5)
    for bad in (5, 3, 0, True, "6"):
        with pytest.raises(SeqOrderError):
            ledger.store(f"h-{bad!r}", "k", "v", "n", bad)
    ledger.deliver("h-1", 6)
    with pytest.raises(SeqOrderError):
        ledger.expire(6)


def test_audit_shapes_and_value_leak_ban():
    ledger = HintedHandoff()
    ledger.store("h-1", "k", "secret-value", "node-a", 1)
    ledger.store("h-2", "k2", "v2", "node-a", 2, ttl_seqs=1)  # expires at 3
    ledger.deliver("h-1", 3)
    ledger.expire(4)
    for row in ledger.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == HINTED_HANDOFF_VERSION
        detail = row["detail"]
        assert "value" not in detail
        assert "payload" not in detail
        assert "secret-value" not in str(row)
    kinds = {row["kind"] for row in ledger.audit_log()}
    assert {KIND_STORED, KIND_DELIVERED, KIND_EXPIRED} <= kinds
    with pytest.raises(hinted_handoff.HintedHandoffError):
        hinted_handoff_audit_event("nope", {}, 1)
    with pytest.raises(hinted_handoff.HintedHandoffError):
        hinted_handoff_audit_event(KIND_STORED, {"value": "x"}, 1)


def test_frozen_records():
    import dataclasses
    ledger = HintedHandoff()
    rec = ledger.store("h-1", "k", "v", "n", 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.status = STATUS_DELIVERED  # type: ignore


def test_cross_instance_digest_determinism():
    a = HintedHandoff()
    b = HintedHandoff()
    ra = a.store("h-1", "k", "v", "node-a", 1, ttl_seqs=5)
    rb = b.store("h-1", "k", "v", "node-a", 1, ttl_seqs=5)
    assert ra.digest == rb.digest
    ea = a.expire(6)
    eb = b.expire(6)
    assert ea.digest == eb.digest


def test_stats_and_unknown_hint_views():
    ledger = HintedHandoff()
    stats = ledger.stats()
    assert stats["total"] == 0
    assert stats["last_seq"] == -1
    assert stats["schema"] == HINTED_HANDOFF_SCHEMA
    assert ledger.hint("nope") is None
    ledger.store("h-1", "k", "v", "n", 1)
    assert ledger.stats()["last_seq"] == 1


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, hinted_handoff.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "hinted-handoff OK" in proc.stdout
