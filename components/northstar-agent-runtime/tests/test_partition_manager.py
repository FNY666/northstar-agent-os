"""Tests for partition_manager (range-based sharding bookkeeping)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import partition_manager as pm

HERE = Path(__file__).resolve().parent
MODULE = HERE.parent / "partition_manager.py"


# ---------------------------------------------------------------------------
# pins / stdlib / self-check
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert pm.PARTITION_MANAGER_VERSION == "partition-manager.v1"
    assert pm.PARTITION_MANAGER_SCHEMA == "northstar.partition-manager.v1"
    assert pm.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing",
        "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("partition-manager OK")


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


def test_create_roundtrip_and_verify():
    mgr = pm.PartitionManager()
    record = mgr.create("p0", "a", "z", 0)
    assert record.partition_id == "p0"
    assert record.key_low == "a" and record.key_high == "z"
    assert record.digest.startswith("sha256:")
    assert record.verify()
    assert mgr.partition("p0") == record
    assert mgr.partition_ids() == ("p0",)


def test_create_duplicate_and_retired_refused():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "m", 0)
    with pytest.raises(pm.PartitionManagerError):
        mgr.create("p0", "m", "z", 1)  # duplicate live id
    mgr.split("p0", "p1", "p2", "g", 2)
    with pytest.raises(pm.PartitionManagerError):
        mgr.create("p0", "a", "m", 3)  # retired id never recycled


def test_create_bad_inputs():
    mgr = pm.PartitionManager()
    with pytest.raises(pm.BadPartitionError):
        mgr.create("", "a", "z", 0)
    with pytest.raises(pm.BadPartitionError):
        mgr.create(True, "a", "z", 0)
    with pytest.raises(pm.BadPartitionError):
        mgr.create("p0", 123, "z", 0)



def test_create_low_ge_high_refused():
    mgr = pm.PartitionManager()
    with pytest.raises(pm.PartitionManagerError):
        mgr.create("p0", "z", "a", 0)
    with pytest.raises(pm.PartitionManagerError):
        mgr.create("p1", "a", "a", 1)


def test_create_overlap_refused():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "m", 0)
    # Contained, containing, left-overlap, right-overlap all refused.
    with pytest.raises(pm.OverlapError):
        mgr.create("p1", "b", "l", 1)
    with pytest.raises(pm.OverlapError):
        mgr.create("p2", "a", "z", 2)
    with pytest.raises(pm.OverlapError):
        mgr.create("p3", "", "b", 3)
    with pytest.raises(pm.OverlapError):
        mgr.create("p4", "l", "z", 4)
    # Touching at the boundary is NOT an overlap.
    mgr.create("p5", "m", "z", 5)
    assert mgr.partition_ids() == ("p0", "p5")


# ---------------------------------------------------------------------------
# split
# ---------------------------------------------------------------------------


def test_split_roundtrip():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "z", 0)
    left, right = mgr.split("p0", "p1", "p2", "n", 1)
    assert (left.key_low, left.key_high) == ("a", "n")
    assert (right.key_low, right.key_high) == ("n", "z")
    assert left.verify() and right.verify()
    assert mgr.partition_ids() == ("p1", "p2")
    assert mgr.retired_ids() == ("p0",)
    with pytest.raises(pm.UnknownPartitionError):
        mgr.partition("p0")


def test_split_bad_key_refused():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "z", 0)
    with pytest.raises(pm.PartitionManagerError):
        mgr.split("p0", "p1", "p2", "a", 1)  # at low boundary
    with pytest.raises(pm.PartitionManagerError):
        mgr.split("p0", "p1", "p2", "z", 2)  # at high boundary
    with pytest.raises(pm.PartitionManagerError):
        mgr.split("p0", "p1", "p2", "zz", 3)  # outside range
    with pytest.raises(pm.UnknownPartitionError):
        mgr.split("nope", "p1", "p2", "m", 4)


def test_split_child_collision_refused():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "m", 0)
    mgr.create("q0", "m", "z", 1)
    with pytest.raises(pm.PartitionManagerError):
        mgr.split("p0", "q0", "p2", "g", 2)  # left_id taken
    with pytest.raises(pm.PartitionManagerError):
        mgr.split("p0", "p1", "p1", "g", 3)  # left == right


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------


def test_merge_roundtrip():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "m", 0)
    mgr.create("p1", "m", "z", 1)
    merged = mgr.merge("p0", "p1", "p2", 2)
    assert (merged.key_low, merged.key_high) == ("a", "z")
    assert merged.verify()
    assert mgr.partition_ids() == ("p2",)
    assert mgr.retired_ids() == ("p0", "p1")


def test_merge_not_adjacent_refused():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "m", 0)
    mgr.create("p1", "n", "z", 1)  # gap between m and n
    with pytest.raises(pm.NotAdjacentError):
        mgr.merge("p0", "p1", "p2", 2)
    mgr.create("p3", "m", "n", 3)
    with pytest.raises(pm.NotAdjacentError):
        mgr.merge("p1", "p0", "p4", 4)  # reversed order is not adjacency
    with pytest.raises(pm.PartitionManagerError):
        mgr.merge("p0", "p0", "p5", 5)  # self-merge


# ---------------------------------------------------------------------------
# route
# ---------------------------------------------------------------------------


def test_route_roundtrip_and_boundaries():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "m", 0)
    mgr.create("p1", "m", "z", 1)
    assert mgr.route("a", 2).partition_id == "p0"  # low inclusive
    assert mgr.route("l", 3).partition_id == "p0"
    assert mgr.route("m", 4).partition_id == "p1"  # high exclusive
    assert mgr.route("y", 5).partition_id == "p1"
    report = mgr.route("l", 6)
    assert report.key_low == "a" and report.key_high == "m"


def test_route_no_coverage_refused():
    mgr = pm.PartitionManager()
    with pytest.raises(pm.NoCoverageError):
        mgr.route("a", 0)  # no partitions at all
    mgr.create("p0", "m", "z", 1)
    with pytest.raises(pm.NoCoverageError):
        mgr.route("a", 2)


# ---------------------------------------------------------------------------
# seq discipline / audit / views
# ---------------------------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "z", 0)
    with pytest.raises(pm.SeqOrderError):
        mgr.create("p1", "a", "z", 0)  # rewind
    with pytest.raises(pm.SeqOrderError):
        mgr.create("p1", "a", "z", True)  # bool is not int
    # Failed mutation consumes its seq: next valid call must use a fresh seq.
    with pytest.raises(pm.OverlapError):
        mgr.create("p1", "a", "b", 1)
    with pytest.raises(pm.SeqOrderError):
        mgr.create("p1", "a", "b", 1)
    stats = mgr.stats()
    assert stats["last_seq"] == 1
    # Pure reads validate seq shape but do not consume it.
    mgr.route("a", 0)
    mgr.partition_ids()
    assert mgr.stats()["last_seq"] == 1


def test_audit_shapes_and_bad_kind():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "z", 0)
    mgr.split("p0", "p1", "p2", "n", 1)
    mgr.merge("p1", "p2", "p3", 2)
    with pytest.raises(pm.OverlapError):
        mgr.create("p4", "a", "b", 3)
    kinds = [row["kind"] for row in mgr.audit_log()]
    assert kinds == [
        pm.KIND_CREATED, pm.KIND_SPLIT, pm.KIND_MERGED, pm.KIND_REJECTED,
    ]
    for row in mgr.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "partition-manager"
        assert row["module_version"] == "partition-manager.v1"
    with pytest.raises(pm.PartitionManagerError):
        pm.partition_manager_audit_event("bogus-kind", 0)
    with pytest.raises(pm.PartitionManagerError):
        pm.partition_manager_audit_event(pm.KIND_CREATED, 0, key="leak")


def test_stats_views():
    mgr = pm.PartitionManager()
    mgr.create("p0", "a", "m", 0)
    mgr.create("p1", "m", "z", 1)
    stats = mgr.stats()
    assert stats["live_partitions"] == 2
    assert stats["retired_partitions"] == 0
    assert stats["splits"] == 0 and stats["merges"] == 0
    mgr.split("p0", "p2", "p3", "g", 2)
    stats = mgr.stats()
    assert stats["live_partitions"] == 3
    assert stats["retired_partitions"] == 1
    assert stats["splits"] == 1
    assert mgr.partition_ids() == ("p1", "p2", "p3")
