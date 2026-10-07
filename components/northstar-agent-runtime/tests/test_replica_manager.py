"""Tests for replica_manager.py — 15 tests."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import replica_manager as rm

MODULE_PATH = Path(rm.__file__)


def test_version_and_schema_pins():
    assert rm.REPLICA_MANAGER_VERSION == "replica-manager.v1"
    assert rm.REPLICA_MANAGER_SCHEMA == "northstar.replica-manager.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "annotations",
        "__future__",
        "hashlib",
        "threading",
        "dataclass",
        "dataclasses",
        "typing",
        "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed | {"canonical_json"}, a.name
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            assert mod in allowed | {"canonical_json"}, mod


def test_replicate_roundtrip():
    mgr = rm.ReplicaManager()
    rec = mgr.replicate("orders", "host-a", 1)
    assert rec.shard_id == "orders" and rec.replica_id == "host-a"
    assert rec.role == rm.ROLE_SECONDARY and rec.epoch == 0
    assert rec.verify()
    assert mgr.replicas("orders", 2) == ("host-a",)


def test_replicate_duplicate_and_bad_ids():
    mgr = rm.ReplicaManager()
    mgr.replicate("orders", "host-a", 1)
    with pytest.raises(rm.DuplicateReplicaError):
        mgr.replicate("orders", "host-a", 2)
    for bad_shard in ("", "  ", "a b", 123, None):
        with pytest.raises(rm.ReplicaManagerError):
            mgr.replicate(bad_shard, "host-b", 3)
    # Duplicate uses fresh seq each time (failed mutations consume seq).
    with pytest.raises(rm.DuplicateReplicaError):
        mgr.replicate("orders", "host-a", 8)


def test_promote_happy_path_and_fencing_epoch():
    mgr = rm.ReplicaManager()
    mgr.replicate("orders", "host-a", 1)
    mgr.replicate("orders", "host-b", 2)
    p1 = mgr.promote("orders", "host-a", 3)
    assert p1.verify() and p1.changed and p1.epoch == 1 and p1.old_primary is None
    assert mgr.primary("orders", 4) == "host-a"
    p2 = mgr.promote("orders", "host-b", 5)
    assert p2.verify() and p2.old_primary == "host-a" and p2.epoch == 2
    assert mgr.primary("orders", 6) == "host-b"
    assert mgr.epoch("orders", 7) == 2
    # Old primary is demoted, not removed.
    assert mgr.replicas("orders", 8) == ("host-a", "host-b")


def test_promote_idempotent_current_primary():
    mgr = rm.ReplicaManager()
    mgr.replicate("orders", "host-a", 1)
    mgr.promote("orders", "host-a", 2)
    p = mgr.promote("orders", "host-a", 3)
    assert not p.changed and p.epoch == 1
    assert mgr.primary("orders", 4) == "host-a"


def test_promote_refusals():
    mgr = rm.ReplicaManager()
    with pytest.raises(rm.UnknownShardError):
        mgr.promote("ghost", "host-a", 1)
    mgr.replicate("orders", "host-a", 2)
    with pytest.raises(rm.PromotionError):
        mgr.promote("orders", "host-z", 3)
    kinds = [e["event"] for e in mgr.audit_log()]
    assert rm.EVENT_REJECTED in kinds


def test_sync_progress_and_monotone():
    mgr = rm.ReplicaManager()
    mgr.replicate("orders", "host-a", 1)
    mgr.replicate("orders", "host-b", 2)
    s1 = mgr.sync("orders", "host-a", 10, 3)
    assert s1.verify() and s1.applied_total == 10
    s2 = mgr.sync("orders", "host-a", 5, 4)
    assert s2.applied_total == 15
    st = mgr.sync_state("orders", "host-a", 5)
    assert st.applied_total == 15 and st.lag == 0
    # host-b is behind: lag measured against shard head.
    stb = mgr.sync_state("orders", "host-b", 6)
    assert stb.applied_total == 0 and stb.lag == 15


def test_sync_bad_payloads_and_unknown():
    mgr = rm.ReplicaManager()
    mgr.replicate("orders", "host-a", 1)
    seq = 2
    for bad in (0, -1, True, "3", 2.5):
        with pytest.raises(rm.BadSyncError):
            mgr.sync("orders", "host-a", bad, seq)
        seq += 1
    with pytest.raises(rm.UnknownReplicaError):
        mgr.sync("orders", "host-z", 1, seq)
    with pytest.raises(rm.UnknownShardError):
        mgr.sync("ghost", "host-a", 1, seq + 1)


def test_seq_discipline_rewind_and_bool():
    mgr = rm.ReplicaManager()
    mgr.replicate("orders", "host-a", 1)
    with pytest.raises(rm.SeqOrderError):
        mgr.replicate("orders", "host-b", 1)  # rewind
    with pytest.raises(rm.SeqOrderError):
        mgr.replicate("orders", "host-b", True)  # bool
    with pytest.raises(rm.SeqOrderError):
        mgr.replicate("orders", "host-b", -2)  # negative


def test_failed_mutation_consumes_seq():
    mgr = rm.ReplicaManager()
    mgr.replicate("orders", "host-a", 1)
    with pytest.raises(rm.DuplicateReplicaError):
        mgr.replicate("orders", "host-a", 2)
    # seq 2 was burned by the failed mutation; reusing it fails.
    with pytest.raises(rm.SeqOrderError):
        mgr.replicate("orders", "host-b", 2)
    # seq 3 works.
    rec = mgr.replicate("orders", "host-b", 3)
    assert rec.verify()
    kinds = [e["event"] for e in mgr.audit_log()]
    assert rm.EVENT_REJECTED in kinds


def test_views_pure_read():
    mgr = rm.ReplicaManager()
    assert mgr.shard_ids(1) == ()
    mgr.replicate("orders", "host-a", 1)
    assert mgr.shard_ids(2) == ("orders",)
    assert mgr.replicas("ghost", 3) == ()
    assert mgr.primary("ghost", 4) is None
    assert mgr.epoch("ghost", 5) == 0
    stats = mgr.stats(6)
    assert stats["shards"] == 1 and stats["replicas"] == 1 and stats["primaries"] == 0
    # Bad seq shapes refused on views too.
    with pytest.raises(rm.SeqOrderError):
        mgr.shard_ids(True)


def test_audit_shapes_and_bad_kind():
    evt = rm.replica_manager_audit_event(rm.EVENT_REPLICATED, "s", "r", 1, role="secondary")
    assert evt["type"] == "audit.ndjson/1"
    assert evt["event"] == rm.EVENT_REPLICATED
    assert evt["schema"] == "northstar.replica-manager.v1"
    with pytest.raises(rm.AuditKindError):
        rm.replica_manager_audit_event("nope", "s", "r", 1)
    with pytest.raises(rm.SeqOrderError):
        rm.replica_manager_audit_event(rm.EVENT_SYNCED, "s", "r", 0)
    mgr = rm.ReplicaManager()
    mgr.replicate("orders", "host-a", 1)
    rows = mgr.audit_log()
    assert rows[0]["event"] == rm.EVENT_REPLICATED
    assert all(r["type"] == "audit.ndjson/1" for r in rows)


def test_record_tamper_rejected():
    mgr = rm.ReplicaManager()
    rec = mgr.replicate("orders", "host-a", 1)
    tampered = rm.ReplicaRecord(
        rec.shard_id, "host-evil", rec.role, rec.epoch, rec.seq, rec.digest
    )
    assert not tampered.verify()


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "replica-manager OK: replicate, promote, sync, fencing, fail-closed"
    )
