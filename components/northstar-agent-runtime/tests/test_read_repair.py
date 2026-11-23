"""Tests for read_repair: Dynamo-style read repair bookkeeping."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import read_repair
from read_repair import (
    BadDigestError,
    BadKeyError,
    BadReplicaError,
    BadReadingError,
    DuplicateReplicaError,
    QuorumNotMetError,
    ReadRepair,
    ReadRepairError,
    ReplicaReading,
    SeqOrderError,
    read_repair_audit_event,
)


def _digest(v: str) -> str:
    return read_repair._pin("value", v)


def _reading(rid: str, ts: int, node: str, val: str) -> ReplicaReading:
    return ReplicaReading(rid, ts, node, _digest(val))


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert read_repair.READ_REPAIR_VERSION == "read-repair.v1"
    assert read_repair.READ_REPAIR_SCHEMA == "northstar.read-repair.v1"
    assert read_repair.AUDIT_SCHEMA == "audit.ndjson/1"
    rr = ReadRepair()
    assert rr.quorum().schema == read_repair.READ_REPAIR_SCHEMA


# ---------------------------------------------------------------------------
# 2. stdlib-only
# ---------------------------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(Path(read_repair.__file__).read_text())
    allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing",
               "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 3. main() self-check
# ---------------------------------------------------------------------------


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, read_repair.__file__],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "read-repair OK" in proc.stdout


# ---------------------------------------------------------------------------
# 4-6. read behaviour
# ---------------------------------------------------------------------------


def test_read_convergent():
    rr = ReadRepair()
    rep = rr.read("k", (_reading("r1", 5, "n1", "a"),
                        _reading("r2", 5, "n1", "a")), 1)
    assert rep.key == "k"
    assert rep.read_id == "read-0"
    assert rep.replica_ids == ("r1", "r2")
    assert not rep.divergent
    assert rep.stale_replicas == ()
    assert rep.winner_digest == _digest("a")
    assert rep.verify()


def test_read_divergent_winner_is_max_timestamp():
    rr = ReadRepair()
    rep = rr.read("k", (_reading("r1", 5, "n1", "a"),
                        _reading("r2", 7, "n1", "b"),
                        _reading("r3", 6, "n2", "a")), 1)
    assert rep.divergent
    assert rep.winner_digest == _digest("b")
    assert rep.winner_ts_seq == 7 and rep.winner_ts_node == "n1"
    assert rep.stale_replicas == ("r1", "r3")
    assert rep.verify()


def test_read_tie_breaks_on_ts_node():
    rr = ReadRepair()
    rep = rr.read("k", (_reading("r1", 5, "n-a", "x"),
                        _reading("r2", 5, "n-b", "y")), 1)
    assert rep.winner_ts_node == "n-b"
    assert rep.winner_digest == _digest("y")
    assert rep.stale_replicas == ("r1",)


# ---------------------------------------------------------------------------
# 7-9. read refusals
# ---------------------------------------------------------------------------


def test_read_quorum_not_met_fails_closed():
    rr = ReadRepair()
    with pytest.raises(QuorumNotMetError):
        rr.read("k", (_reading("r1", 1, "n1", "a"),), 1)
    assert rr.audit_log()[-1]["kind"] == read_repair.KIND_REJECTED
    with pytest.raises(SeqOrderError):  # failed mutation consumed seq 1
        rr.read("k", (_reading("r1", 1, "n1", "a"),
                      _reading("r2", 1, "n1", "a")), 1)


def test_read_duplicate_replica_refused():
    rr = ReadRepair()
    with pytest.raises(DuplicateReplicaError):
        rr.read("k", (_reading("r1", 1, "n1", "a"),
                      _reading("r1", 2, "n1", "b")), 1)


def test_read_bad_inputs_refused():
    rr = ReadRepair()
    ok = (_reading("r1", 1, "n1", "a"), _reading("r2", 1, "n1", "a"))
    with pytest.raises(BadKeyError):
        rr.read("", ok, 1)
    with pytest.raises(BadReadingError):
        rr.read("k", list(ok), 2)  # not a tuple
    with pytest.raises(BadDigestError):
        rr.read("k", (ReplicaReading("r1", 1, "n1", "nope"),
                      ReplicaReading("r2", 1, "n1", _digest("a"))), 3)
    with pytest.raises(BadReplicaError):
        rr.read("k", (_reading("", 1, "n1", "a"), _reading("r2", 1, "n1", "a")), 4)


# ---------------------------------------------------------------------------
# 10-12. reconcile
# ---------------------------------------------------------------------------


def test_reconcile_roundtrip():
    rr = ReadRepair()
    rep = rr.read("k", (_reading("r1", 5, "n1", "a"),
                        _reading("r2", 7, "n1", "b")), 1)
    rec = rr.reconcile("k", rep.winner_digest, rep.winner_ts_seq,
                       rep.winner_ts_node, rep.stale_replicas, 2)
    assert rec.reconcile_id == "reconcile-0"
    assert rec.stale_replicas == ("r1",)
    assert rec.winner_digest == _digest("b")
    assert rec.verify()
    assert rr.audit_log()[-1]["kind"] == read_repair.KIND_RECONCILED


def test_reconcile_empty_stale_refused():
    rr = ReadRepair()
    with pytest.raises(BadReplicaError):
        rr.reconcile("k", _digest("b"), 7, "n1", (), 1)


def test_reconcile_bad_inputs_refused():
    rr = ReadRepair()
    with pytest.raises(BadDigestError):
        rr.reconcile("k", "bad", 7, "n1", ("r1",), 1)
    with pytest.raises(DuplicateReplicaError):
        rr.reconcile("k", _digest("b"), 7, "n1", ("r1", "r1"), 2)


# ---------------------------------------------------------------------------
# 13. quorum view
# ---------------------------------------------------------------------------


def test_quorum_view_defaults_and_custom():
    rr = ReadRepair(num_replicas=5)
    cfg = rr.quorum()
    assert (cfg.num_replicas, cfg.read_quorum, cfg.write_quorum) == (5, 3, 3)
    rr2 = ReadRepair(num_replicas=5, read_quorum=4, write_quorum=1)
    cfg2 = rr2.quorum()
    assert (cfg2.read_quorum, cfg2.write_quorum) == (4, 1)
    with pytest.raises(ReadRepairError):
        ReadRepair(num_replicas=3, read_quorum=4)


# ---------------------------------------------------------------------------
# 14. seq discipline
# ---------------------------------------------------------------------------


def test_seq_ordering():
    rr = ReadRepair()
    rr.read("k", (_reading("r1", 1, "n1", "a"),
                  _reading("r2", 1, "n1", "a")), 2)
    with pytest.raises(SeqOrderError):
        rr.read("k", (_reading("r1", 1, "n1", "a"),
                      _reading("r2", 1, "n1", "a")), 2)  # rewind
    with pytest.raises(SeqOrderError):
        rr.read("k", (_reading("r1", 1, "n1", "a"),
                      _reading("r2", 1, "n1", "a")), True)  # bool
    with pytest.raises(SeqOrderError):
        rr.read("k", (_reading("r1", 1, "n1", "a"),
                      _reading("r2", 1, "n1", "a")), -1)  # negative


# ---------------------------------------------------------------------------
# 15. audit shapes
# ---------------------------------------------------------------------------


def test_audit_shapes_and_bans():
    row = read_repair_audit_event(
        read_repair.KIND_READ, {"key": "k", "winner_digest": _digest("a")}, 1
    )
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "read-repair.v1"
    with pytest.raises(ReadRepairError):
        read_repair_audit_event("nope", {}, 1)
    with pytest.raises(ReadRepairError):
        read_repair_audit_event(read_repair.KIND_READ, {"value": "a"}, 1)
