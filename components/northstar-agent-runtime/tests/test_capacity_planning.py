"""Tests for capacity_planning.py (15 tests)."""

import ast
import os
import subprocess
import sys

import pytest

import capacity_planning as cp_mod
from capacity_planning import (
    CapacityPlanning,
    BadWorkloadError,
    DuplicateWorkloadError,
    UnknownWorkloadError,
    BadUtilizationError,
    BadForecastError,
    SeqOrderError,
    capacity_planning_audit_event,
)


def fresh():
    return CapacityPlanning()


def reg(cp, wid="w1", rtype="ec2", seq=1):
    return cp.register_workload(wid, rtype, seq, current_size="m5.large")


def sample(cp, wid="w1", cpu=50.0, mem=50.0, seq=2):
    return cp.record_utilization(wid, cpu, mem, seq)


# 1 ---------------------------------------------------------------------


def test_version_pins():
    assert cp_mod.CAPACITY_PLANNING_VERSION == "capacity-planning.v1"
    assert cp_mod.CAPACITY_PLANNING_SCHEMA == "northstar.capacity-planning.v1"
    assert cp_mod.AUDIT_SCHEMA == "audit.ndjson/1"


# 2 ---------------------------------------------------------------------


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "capacity_planning.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3 ---------------------------------------------------------------------


def test_register_roundtrip():
    cp = fresh()
    r1 = reg(cp)
    assert r1.workload_id == "w1" and r1.resource_type == "ec2"
    assert r1.current_size == "m5.large" and r1.verify()
    try:
        r1.resource_type = "x"  # type: ignore[misc]
    except Exception as exc:
        assert type(exc).__name__ == "FrozenInstanceError"
    else:
        raise AssertionError("records must be frozen")
    other = CapacityPlanning()
    r2 = reg(other)
    assert r1.digest == r2.digest  # cross-instance determinism
    assert cp.workload("w1").digest == r1.digest
    assert cp.workload_ids() == ("w1",)


# 4 ---------------------------------------------------------------------


def test_register_bad_inputs():
    cp = fresh()
    bad = [
        dict(wid="", rtype="ec2"),            # empty id
        dict(wid="   ", rtype="ec2"),         # blank id
        dict(wid="w1", rtype="gke"),          # bad resource type
        dict(wid="w1", rtype="EC2"),          # case-sensitive vocab
        dict(wid="w1", rtype=42),             # non-string type
        dict(wid=123, rtype="ec2"),           # non-string id
    ]
    seq = 1
    for case in bad:
        seq += 1
        with pytest.raises((BadWorkloadError, cp_mod.CapacityPlanningError)):
            cp.register_workload(case["wid"], case["rtype"], seq)
    cp2 = fresh()
    reg(cp2, seq=1)
    with pytest.raises(DuplicateWorkloadError):
        cp2.register_workload("w1", "ec2", 2)


# 5 ---------------------------------------------------------------------


def test_record_utilization_roundtrip_chain():
    cp = fresh()
    reg(cp)
    s1 = sample(cp, seq=2)
    assert s1.sample_id == "utl-1" and s1.prev_digest == "genesis"
    assert s1.verify()
    s2 = sample(cp, cpu=30.0, mem=40.0, seq=3)
    assert s2.sample_id == "utl-2" and s2.prev_digest == s1.digest
    assert s2.verify()
    samples = cp.samples_for("w1")
    assert len(samples) == 2 and samples[0].digest == s1.digest


# 6 ---------------------------------------------------------------------


def test_record_utilization_bad_inputs():
    cp = fresh()
    reg(cp)
    bad = [
        ("w1", -1.0, 50.0),     # negative cpu
        ("w1", 50.0, 100.1),    # mem over 100
        ("w1", True, 50.0),     # bool cpu refused
        ("w1", "50", 50.0),     # string cpu refused
        ("w1", float("nan"), 50.0),  # NaN refused
        ("w1", float("inf"), 50.0),  # inf refused
        ("nope", 50.0, 50.0),   # unknown workload
    ]
    seq = 10
    for wid, cpu, mem in bad:
        seq += 1
        with pytest.raises((BadUtilizationError, UnknownWorkloadError)):
            cp.record_utilization(wid, cpu, mem, seq)


# 7 ---------------------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    cp = fresh()
    reg(cp)
    with pytest.raises(SeqOrderError):
        cp.register_workload("w2", "ec2", 1)  # rewind
    with pytest.raises(SeqOrderError):
        cp.register_workload("w2", "ec2", True)  # bool
    with pytest.raises(SeqOrderError):
        cp.record_utilization("w1", 1.0, 1.0, -1)  # negative
    # failed mutation consumes its seq
    with pytest.raises(BadWorkloadError):
        cp.register_workload("w2", "bogus-type", 2)
    with pytest.raises(SeqOrderError):
        cp.register_workload("w2", "ec2", 2)  # seq 2 already consumed


# 8 ---------------------------------------------------------------------


def test_forecast_math_and_pure_view():
    cp = fresh()
    reg(cp)
    sample(cp, cpu=10.0, mem=20.0, seq=2)
    sample(cp, cpu=30.0, mem=40.0, seq=3)
    # avg_cpu=20, avg_mem=30, trend_cpu=(30-10)/1=20, trend_mem=20
    fc = cp.forecast("w1", 5, 4)
    assert fc.verify()
    assert fc.avg_cpu == 20.0 and fc.avg_memory == 30.0
    assert fc.trend_cpu == 20.0 and fc.trend_memory == 20.0
    assert fc.projected_cpu == 100.0  # 20 + 20*5 = 120 clamped
    assert fc.projected_memory == 100.0
    assert fc.sample_count == 2
    # pure view: seq not consumed — next mutation may reuse seq 5
    s = cp.record_utilization("w1", 1.0, 1.0, 5)
    assert s.sample_id == "utl-3"


# 9 ---------------------------------------------------------------------


def test_forecast_bad_inputs():
    cp = fresh()
    reg(cp)
    with pytest.raises(UnknownWorkloadError):
        cp.forecast("nope", 5, 1)
    with pytest.raises(BadForecastError):
        cp.forecast("w1", -1, 2)
    with pytest.raises(BadForecastError):
        cp.forecast("w1", True, 3)
    with pytest.raises(SeqOrderError):
        cp.forecast("w1", 5, -1)


# 10 --------------------------------------------------------------------


def test_rightsize_downsize():
    cp = fresh()
    reg(cp)
    sample(cp, cpu=8.0, mem=12.0, seq=2)
    sample(cp, cpu=6.0, mem=10.0, seq=3)
    rec = cp.rightsize("w1", 4)
    assert rec.verify()
    assert rec.recommendation == "downsize"
    assert rec.sample_count == 2


# 11 --------------------------------------------------------------------


def test_rightsize_upsize():
    cp = fresh()
    reg(cp)
    sample(cp, cpu=90.0, mem=50.0, seq=2)  # cpu > 85 → upsize
    rec = cp.rightsize("w1", 3)
    assert rec.recommendation == "upsize"
    cp2 = fresh()
    reg(cp2, seq=1)
    sample(cp2, cpu=50.0, mem=95.0, seq=2)  # mem > 90 → upsize
    assert cp2.rightsize("w1", 3).recommendation == "upsize"


# 12 --------------------------------------------------------------------


def test_rightsize_optimal_and_insufficient():
    cp = fresh()
    reg(cp, wid="busy", seq=1)
    sample(cp, wid="busy", cpu=50.0, mem=60.0, seq=2)
    assert cp.rightsize("busy", 3).recommendation == "optimal"
    reg(cp, wid="fresh", seq=4)
    rec = cp.rightsize("fresh", 5)
    assert rec.recommendation == "insufficient-data"
    assert rec.sample_count == 0
    with pytest.raises(UnknownWorkloadError):
        cp.rightsize("nope", 6)


# 13 --------------------------------------------------------------------


def test_report_aggregation():
    cp = fresh()
    reg(cp, wid="low", seq=1)
    sample(cp, wid="low", cpu=5.0, mem=5.0, seq=2)
    reg(cp, wid="hot", seq=3)
    sample(cp, wid="hot", cpu=99.0, mem=50.0, seq=4)
    reg(cp, wid="mid", seq=5)
    sample(cp, wid="mid", cpu=50.0, mem=50.0, seq=6)
    reg(cp, wid="empty", seq=7)
    rep = cp.report(8)
    assert rep.verify()
    assert rep.total_workloads == 4
    assert rep.with_samples == 3
    assert rep.downsize == 1 and rep.upsize == 1
    assert rep.optimal == 1 and rep.insufficient_data == 1


# 14 --------------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    cp = fresh()
    reg(cp)
    sample(cp, seq=2)
    rows = cp.audit_log()
    assert len(rows) == 2
    assert rows[0]["kind"] == "capacity.workload-registered"
    assert rows[1]["kind"] == "capacity.utilization-recorded"
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert "cpu_pct" not in row["detail"]  # banned key
        assert "memory_pct" not in row["detail"]
    with pytest.raises(cp_mod.CapacityPlanningError):
        capacity_planning_audit_event("bogus-kind", {}, 1)
    with pytest.raises(cp_mod.CapacityPlanningError):
        capacity_planning_audit_event(
            "capacity.utilization-recorded", {"cpu_pct": 1.0}, 1
        )


# 15 --------------------------------------------------------------------


def test_main_subprocess():
    path = os.path.join(os.path.dirname(__file__), "..", "capacity_planning.py")
    out = subprocess.run(
        [sys.executable, path], capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, out.stderr
    assert "capacity-planning OK" in out.stdout
