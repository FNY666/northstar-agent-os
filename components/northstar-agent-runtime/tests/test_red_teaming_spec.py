"""Spec-API tests for red_teaming.py: plan() / execute() / report().

Additive extension coverage: the campaign-ledger half (attack / probe /
report) is tested in test_red_teaming.py; these tests cover the spec's
plan -> execute -> report workflow layer.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from red_teaming import (
    AuditKindError,
    BadDigestError,
    BadObjectiveError,
    DuplicatePlanError,
    ExecuteRecord,
    PlanRecord,
    PlanStateError,
    RedTeaming,
    RedTeamingError,
    SeqOrderError,
    UnknownAttackError,
    UnknownPlanError,
    red_teaming_audit_event,
)

_VALID_DIGEST = "sha256:" + "ab" * 32


def _attacked(seq_start: int = 1):
    rt = RedTeaming()
    rt.attack("a-1", "jailbreak", seq_start)
    return rt, seq_start + 1


def test_spec_api_presence():
    rt = RedTeaming()
    assert callable(rt.plan)
    assert callable(rt.execute)
    assert callable(rt.report)
    assert callable(rt.plan_record)
    assert callable(rt.execution_record)
    assert callable(rt.plan_ids)
    assert callable(rt.plans_for_attack)
    # New audit kinds are registered.
    evt = red_teaming_audit_event("planned", {"plan_id": "p"}, 1)
    assert evt["kind"] == "planned"
    evt = red_teaming_audit_event("executed", {"plan_id": "p"}, 1)
    assert evt["kind"] == "executed"


def test_plan_roundtrip_verify_and_frozen():
    rt, seq = _attacked()
    rec = rt.plan("p-1", "a-1", seq, objective="measure refusal",
                  scenario_digest=_VALID_DIGEST)
    assert isinstance(rec, PlanRecord)
    assert rec.plan_id == "p-1"
    assert rec.attack_id == "a-1"
    assert rec.scenario_digest == _VALID_DIGEST
    assert rec.objective_digest.startswith("sha256:")
    assert len(rec.objective_digest) == len("sha256:") + 64
    assert rec.verify("p-1", "a-1")
    assert not rec.verify("p-1", "a-2")
    # Objective text is digest-pinned, never stored raw.
    assert "measure refusal" not in repr(rec)
    with pytest.raises(AttributeError):
        rec.plan_id = "mutated"  # type: ignore[misc]


def test_plan_objective_never_raw():
    rt, seq = _attacked()
    secret = "super-secret-objective-phrase"
    rec = rt.plan("p-1", "a-1", seq, objective=secret)
    assert secret not in repr(rec)
    assert "objective" not in rec.__dict__
    for row in rt.audit_log():
        assert secret not in repr(row["detail"])
    # The audit boundary refuses raw objective text.
    with pytest.raises(AuditKindError):
        red_teaming_audit_event("planned", {"objective": secret}, seq + 1)
    with pytest.raises(AuditKindError):
        red_teaming_audit_event("executed", {"objective": secret}, seq + 1)


def test_plan_bad_inputs_burn_seq():
    rt, seq = _attacked()
    bad = [
        dict(plan_id="", attack_id="a-1"),
        dict(plan_id=None, attack_id="a-1"),
        dict(plan_id=True, attack_id="a-1"),
        dict(plan_id="bad id!", attack_id="a-1"),
        dict(plan_id="x" * 257, attack_id="a-1"),
        dict(plan_id="p-1", attack_id=""),
        dict(plan_id="p-1", attack_id="nope"),          # unknown attack
        dict(plan_id="p-1", attack_id="a-1", objective=42),
        dict(plan_id="p-1", attack_id="a-1", objective=True),
        dict(plan_id="p-1", attack_id="a-1",
             scenario_digest="raw-text"),
        dict(plan_id="p-1", attack_id="a-1",
             scenario_digest="sha256:" + "zz" * 32),   # non-hex
        dict(plan_id="p-1", attack_id="a-1",
             scenario_digest="sha256:" + "ab" * 31),   # 62 chars
        dict(plan_id="p-1", attack_id="a-1", scenario_digest=42),
    ]
    for kwargs in bad:
        with pytest.raises(RedTeamingError):
            rt.plan(seq=seq, **kwargs)
        seq += 1
    rejected = [e for e in rt.audit_log() if e["kind"] == "rejected"]
    assert len(rejected) == len(bad)


def test_plan_duplicate_refused():
    rt, seq = _attacked()
    rt.plan("p-1", "a-1", seq, objective="o1")
    with pytest.raises(DuplicatePlanError):
        rt.plan("p-1", "a-1", seq + 1, objective="o2")
    rejected = [e for e in rt.audit_log() if e["kind"] == "rejected"]
    assert len(rejected) == 1
    # Original plan untouched.
    assert rt.plan_record("p-1").verify("p-1", "a-1")


def test_plan_unknown_attack_refused():
    rt = RedTeaming()
    with pytest.raises(UnknownAttackError):
        rt.plan("p-1", "nope", 1, objective="o")
    rejected = [e for e in rt.audit_log() if e["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rt.stats()["plans"] == 0


def test_execute_roundtrip_and_verify():
    rt, seq = _attacked()
    rt.plan("p-1", "a-1", seq)
    rec = rt.execute("p-1", seq + 1)
    assert isinstance(rec, ExecuteRecord)
    assert rec.execute_id == "exe-1"
    assert rec.plan_id == "p-1"
    assert rec.attack_id == "a-1"
    assert rec.probes_at_start == 0
    assert rec.verify("p-1")
    assert not rec.verify("p-2")
    # Minted ids increment across plans.
    rt.plan("p-2", "a-1", seq + 2)
    rec2 = rt.execute("p-2", seq + 3)
    assert rec2.execute_id == "exe-2"
    with pytest.raises(AttributeError):
        rec.plan_id = "mutated"  # type: ignore[misc]


def test_execute_unknown_plan_refused():
    rt, seq = _attacked()
    with pytest.raises(UnknownPlanError):
        rt.execute("nope", seq)
    rejected = [e for e in rt.audit_log() if e["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["detail"]["plan_id"] == "nope"
    assert rt.stats()["executions"] == 0


def test_execute_twice_refused():
    rt, seq = _attacked()
    rt.plan("p-1", "a-1", seq)
    rt.execute("p-1", seq + 1)
    with pytest.raises(PlanStateError):
        rt.execute("p-1", seq + 2)
    rejected = [e for e in rt.audit_log() if e["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rt.execution_record("p-1").execute_id == "exe-1"


def test_execute_probes_at_start():
    rt, seq = _attacked()
    rt.plan("p-1", "a-1", seq)
    rt.probe("a-1", "pr-1", seq + 1, "blocked")
    rt.probe("a-1", "pr-2", seq + 2, "breached")
    rec = rt.execute("p-1", seq + 3)
    assert rec.probes_at_start == 2
    # Later probes do not rewrite the booked snapshot.
    rt.probe("a-1", "pr-3", seq + 4, "refused")
    assert rt.execution_record("p-1").probes_at_start == 2


def test_plan_execute_report_flow():
    rt, seq = _attacked()
    rt.plan("p-1", "a-1", seq, objective="full campaign")
    rt.execute("p-1", seq + 1)
    rt.probe("a-1", "pr-1", seq + 2, "blocked")
    rt.probe("a-1", "pr-2", seq + 3, "breached")
    rpt = rt.report("a-1", seq + 4)
    assert rpt.verdict == "vulnerable"   # verdict as data, never raised
    assert rpt.probe_count == 2
    assert rpt.breached_count == 1
    assert rpt.verify("a-1", (1, 1, 0, 0))


def test_execute_seq_discipline():
    rt, seq = _attacked()
    rt.plan("p-1", "a-1", seq)
    rt.execute("p-1", seq + 1)
    # Rewind raises bare: no rejected row, seq not consumed.
    before = len(rt.audit_log())
    with pytest.raises(SeqOrderError):
        rt.execute("p-1", seq + 1)
    with pytest.raises(SeqOrderError):
        rt.plan("p-2", "a-1", seq)
    assert len(rt.audit_log()) == before
    # Malformed seqs rejected.
    for bad in (True, "5", 2.5, None, -1):
        with pytest.raises(SeqOrderError):
            rt.execute("p-1", bad)
    assert len(rt.audit_log()) == before


def test_audit_kinds_and_leak_ban():
    rt, seq = _attacked()
    rt.plan("p-1", "a-1", seq, objective="o")
    rt.execute("p-1", seq + 1)
    rt.probe("a-1", "pr-1", seq + 2, "blocked")
    rt.report("a-1", seq + 3)
    kinds = [e["kind"] for e in rt.audit_log()]
    assert kinds == ["attack-declared", "planned", "executed",
                     "probed", "reported"]
    for e in rt.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert "objective" not in e["detail"]
    planned = rt.audit_log()[1]
    assert planned["detail"] == {"plan_id": "p-1", "attack_id": "a-1"}


def test_views_and_stats():
    rt, seq = _attacked()
    rt.attack("a-2", "tool-abuse", seq)
    rt.plan("p-1", "a-1", seq + 1)
    rt.plan("p-2", "a-2", seq + 2)
    rt.execute("p-1", seq + 3)
    assert rt.plan_ids() == ("p-1", "p-2")
    assert rt.plans_for_attack("a-1") == ("p-1",)
    assert rt.plans_for_attack("a-2") == ("p-2",)
    assert rt.plan_record("p-1").attack_id == "a-1"
    assert rt.execution_record("p-1").execute_id == "exe-1"
    with pytest.raises(UnknownPlanError):
        rt.plan_record("nope")
    with pytest.raises(UnknownPlanError):
        rt.execution_record("p-2")   # planned but not executed
    with pytest.raises(UnknownPlanError):
        rt.execution_record("nope")
    stats = rt.stats()
    assert stats["attacks"] == 2
    assert stats["plans"] == 2
    assert stats["executions"] == 1


def test_main_subprocess():
    import subprocess

    path = Path(__file__).resolve().parent.parent / "red_teaming.py"
    proc = subprocess.run(
        [sys.executable, str(path)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "red-teaming OK" in proc.stdout
