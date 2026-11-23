"""Tests for sloppy_quorum: Dynamo-style quorum read/write ledger."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from sloppy_quorum import (
    AUDIT_SCHEMA,
    KIND_READ,
    KIND_REJECTED,
    KIND_WRITTEN,
    SLOPPY_QUORUM_SCHEMA,
    SLOPPY_QUORUM_VERSION,
    AuditKindError,
    BadNodeError,
    BadQuorumError,
    BadValueError,
    ConfigRecord,
    DuplicateNodeError,
    HintDeliveryRecord,
    HintRecord,
    InsufficientReplicasError,
    NodeRecord,
    ReadReport,
    SeqOrderError,
    SloppyQuorum,
    SloppyQuorumError,
    UnknownKeyError,
    UnknownNodeError,
    WriteRecord,
    sloppy_quorum_audit_event,
)

MOD = Path(__file__).resolve().parent.parent / "sloppy_quorum.py"


def _digest(tag: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(tag.encode("utf-8")).hexdigest()


def fresh(n: int = 3, w: int = 2, r: int = 2) -> SloppyQuorum:
    sq = SloppyQuorum(n=n, w=w, r=r)
    for i, node in enumerate(("n1", "n2", "n3", "n4"), start=1):
        sq.node(node, seq=i)
    return sq


def test_version_pins():
    assert SLOPPY_QUORUM_VERSION == "sloppy-quorum.v1"
    assert SLOPPY_QUORUM_SCHEMA == "northstar.sloppy-quorum.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib", "hmac", "json", "threading", "dataclasses", "typing",
        "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert r.returncode == 0, r.stderr
    assert "sloppy-quorum OK" in r.stdout


def test_node_register_roundtrip_and_duplicate():
    sq = SloppyQuorum()
    rec = sq.node("a", seq=1)
    assert isinstance(rec, NodeRecord)
    assert rec.node_id == "a" and rec.status == "healthy"
    assert rec.verify()
    with pytest.raises(DuplicateNodeError):
        sq.node("a", seq=2)  # failed mutation consumes its seq
    with pytest.raises(SeqOrderError):
        sq.node("b", seq=2)  # seq 2 was consumed by the refusal


def test_node_bad_inputs():
    sq = SloppyQuorum()
    seq = 0
    for bad in ("", "   ", 123, None, True, "x" * 257):
        seq += 1
        with pytest.raises(SloppyQuorumError):
            sq.node(bad, seq=seq)
    kinds = {e["kind"] for e in sq.audit_log()}
    assert KIND_REJECTED in kinds


def test_w_config_roundtrip_and_bad_quorum():
    sq = fresh()
    cfg = sq.w(1, seq=5)
    assert isinstance(cfg, ConfigRecord)
    assert cfg.quorum == 1 and cfg.verify()
    assert sq.quorum_config(seq=6)["w"] == 1
    for bad in (0, 4, -1, True, 1.5, "2"):
        with pytest.raises(BadQuorumError):
            sq.w(bad, seq=sq.stats(seq=6)["last_seq"] + 1)
    assert sq.quorum_config(seq=12)["w"] == 1


def test_write_roundtrip_and_verify():
    sq = fresh()
    rec = sq.write("k", _digest("v1"), seq=5)
    assert isinstance(rec, WriteRecord)
    assert rec.version == 1
    assert rec.value_digest == _digest("v1")
    assert len(rec.placements) == 2  # w=2
    assert not any(p.hinted for p in rec.placements)
    assert rec.verify()
    kinds = [e["kind"] for e in sq.audit_log()]
    assert KIND_WRITTEN in kinds


def test_write_versions_increase():
    sq = fresh()
    d1 = _digest("v1")
    d2 = _digest("v2")
    r1 = sq.write("k", d1, seq=5)
    r2 = sq.write("k", d2, seq=6)
    assert r2.version == r1.version + 1
    assert r2.value_digest == d2


def test_write_sloppy_fallback_books_hints():
    sq = fresh()
    pref = sq.preference_list("k2")
    sq.fail(pref[0], seq=5)
    sq.fail(pref[1], seq=6)
    rec = sq.write("k2", _digest("v1"), seq=7)
    assert rec.verify()
    sloppy = [p for p in rec.placements if p.hinted]
    assert len(sloppy) >= 1
    # Hint rows are booked for the failed owners.
    hints = sq.hints_for(pref[0], seq=8)
    assert any(h.key == "k2" for h in hints)
    # Raw value bytes never cross the audit boundary.
    written = next(e for e in sq.audit_log() if e["kind"] == KIND_WRITTEN)
    assert "value" not in written and "payload" not in written


def test_write_insufficient_replicas_fail_closed():
    sq = SloppyQuorum(n=3, w=2, r=2)
    sq.node("only", seq=1)
    with pytest.raises(InsufficientReplicasError):
        sq.write("k", _digest("v"), seq=2)
    kinds = [e["kind"] for e in sq.audit_log()]
    assert KIND_REJECTED in kinds


def test_write_bad_digest_and_key():
    sq = fresh()
    with pytest.raises(BadValueError):
        sq.write("k", "not-a-digest", seq=5)
    with pytest.raises(BadValueError):
        sq.write("k", "sha256:" + "zz" * 32, seq=6)
    with pytest.raises(SloppyQuorumError):
        sq.write("", _digest("v"), seq=7)


def test_read_roundtrip_and_reconciliation():
    sq = fresh()
    d1 = _digest("v1")
    d2 = _digest("v2")
    sq.write("k", d1, seq=5)
    sq.write("k", d2, seq=6)
    rep = sq.read("k", seq=7)
    assert isinstance(rep, ReadReport)
    assert rep.found
    assert rep.value_digest == d2
    assert rep.version == 2
    assert rep.quorum_met
    assert rep.divergent == 0
    assert rep.verify()
    kinds = [e["kind"] for e in sq.audit_log()]
    assert KIND_READ in kinds


def test_read_unknown_key_is_data():
    sq = fresh()
    rep = sq.read("nope", seq=5)
    assert rep.verify()
    assert not rep.found
    assert rep.version == 0
    assert not rep.quorum_met


def test_hint_delivery_and_read_repair_targets():
    sq = fresh()
    pref = sq.preference_list("k2")
    sq.fail(pref[0], seq=5)
    sq.fail(pref[1], seq=6)
    sq.write("k2", _digest("v1"), seq=7)
    # Recover the owner and deliver its hints.
    sq.recover(pref[0], seq=8)
    hints = sq.hints_for(pref[0], seq=9)
    assert hints
    seq = 10
    for h in hints:
        assert isinstance(h, HintRecord) and h.verify()
        rec = sq.deliver_hint(h.owner_id, h.holder_id, h.key, seq=seq)
        assert isinstance(rec, HintDeliveryRecord) and rec.verify()
        seq += 1
    assert sq.hints_for(pref[0], seq=100) == ()
    with pytest.raises(UnknownKeyError):
        sq.deliver_hint(pref[0], "nobody", "k2", seq=101)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    sq = fresh()
    with pytest.raises(SeqOrderError):
        sq.node("late", seq=4)  # rewind
    with pytest.raises(SeqOrderError):
        sq.write("k", _digest("v"), seq="5")  # non-int
    with pytest.raises(SeqOrderError):
        sq.w(2, seq=True)  # bool refused
    # Views validate shape but never consume.
    last = sq.stats(seq=5)["last_seq"]
    assert sq.stats(seq=5)["last_seq"] == last
    with pytest.raises(SeqOrderError):
        sq.stats(seq=0)


def test_audit_shapes_and_banned_keys_and_bad_kind():
    sq = fresh()
    sq.write("k", _digest("v"), seq=5)
    for e in sq.audit_log():
        assert e["schema"] == AUDIT_SCHEMA
        assert "value" not in e and "value_bytes" not in e
        assert "payload" not in e and "body" not in e
    with pytest.raises(AuditKindError):
        sloppy_quorum_audit_event("nope", 1)
    with pytest.raises(AuditKindError):
        sloppy_quorum_audit_event(KIND_READ, 1, value="raw")
