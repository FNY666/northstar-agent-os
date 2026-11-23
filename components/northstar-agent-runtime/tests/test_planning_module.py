"""Tests for planning_module: task-decomposition planning ledger."""

import ast
import subprocess
import sys

import pytest

import planning_module as pm
from planning_module import PlanningModule


def _module_path():
    return pm.__file__


def _plan(p, goal="g", plan="p1"):
    p.goal(goal, "ship it", 1)
    return p.decompose(goal, plan, [("a", "step a"), ("b", "step b"),
                                    ("c", "step c")], 2)


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert pm.PLANNING_MODULE_VERSION == "planning-module.v1"
    assert pm.PLANNING_MODULE_SCHEMA == "northstar.planning-module.v1"
    assert pm.AUDIT_SCHEMA == "audit.ndjson/1"
    assert pm.OUTCOMES == ("done", "failed", "skipped")


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "collections",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# goal
# ---------------------------------------------------------------------------


def test_goal_roundtrip_and_digest():
    p = PlanningModule()
    rec = p.goal("launch", "ship the runtime", 1)
    assert rec.goal_id == "launch"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("launch")
    assert not rec.verify("other")
    assert p.goal_record("launch") == rec
    assert p.goal_record("nope") is None
    assert p.goal_ids() == ("launch",)


def test_goal_duplicate_and_bad_inputs_consume_seq_and_audit_rejected():
    p = PlanningModule()
    p.goal("g", "d", 1)
    cases = [
        (lambda: p.goal("g", "again", 2), pm.DuplicateGoalError),
        (lambda: p.goal("", "d", 3), pm.BadGoalError),
        (lambda: p.goal("has space", "d", 4), pm.BadGoalError),
        (lambda: p.goal(123, "d", 5), pm.BadGoalError),
        (lambda: p.goal("g2", "", 6), pm.BadGoalError),
        (lambda: p.goal("g2", "x" * 1025, 7), pm.BadGoalError),
    ]
    for fn, exc in cases:
        with pytest.raises(exc):
            fn()
    rejected = [r for r in p.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == len(cases)
    assert [r["seq"] for r in rejected] == [2, 3, 4, 5, 6, 7]
    # Seq space consumed: next valid seq must exceed 7.
    with pytest.raises(pm.SeqOrderError):
        p.goal("ok", "d", 7)
    p.goal("ok", "d", 8)


# ---------------------------------------------------------------------------
# decompose
# ---------------------------------------------------------------------------


def test_decompose_roundtrip_and_verify():
    p = PlanningModule()
    rec = _plan(p)
    assert rec.plan_id == "p1"
    assert rec.goal_id == "g"
    assert rec.step_ids == ("a", "b", "c")
    assert rec.descriptions == ("step a", "step b", "step c")
    assert rec.verify("p1", "g", ("a", "b", "c"), 2)
    assert not rec.verify("p1", "g", ("a", "b"), 2)
    assert p.plan_record("p1") == rec
    assert p.plan_ids() == ("p1",)
    # Records are frozen.
    with pytest.raises(AttributeError):
        rec.plan_id = "x"  # type: ignore[misc]


def test_decompose_bad_inputs():
    p = PlanningModule()
    p.goal("g", "d", 1)
    good_steps = [("a", "da"), ("b", "db")]
    with pytest.raises(pm.UnknownGoalError):
        p.decompose("missing", "p1", good_steps, 2)
    bad = [
        ([], pm.BadPlanError),                                   # empty
        ("not-a-sequence-of-pairs", pm.BadPlanError),            # str
        ([("a", "da"), ("a", "db")], pm.DuplicateStepError),     # dup id
        ([("has space", "d")], pm.BadStepError),                 # bad id
        ([("a", "")], pm.BadGoalError),                          # bad desc
        ([("a",)], pm.BadPlanError),                             # bad pair
        ([("a", "da", "extra")], pm.BadPlanError),               # bad pair
        (None, pm.BadPlanError),
    ]
    seq = 3
    for steps, exc in bad:
        with pytest.raises(exc):
            p.decompose("g", "pX", steps, seq)
        seq += 1
    # "p1" was never booked (the seq-2 attempt died on the unknown goal),
    # so the first booking succeeds and only the next ones collide.
    p.decompose("g", "p1", good_steps, seq)
    with pytest.raises(pm.DuplicatePlanError):
        p.decompose("g", "p1", good_steps, seq + 1)
    with pytest.raises(pm.DuplicatePlanError):
        p.decompose("g", "p1", good_steps, seq + 2)


# ---------------------------------------------------------------------------
# sequence
# ---------------------------------------------------------------------------


def test_sequence_roundtrip_and_deterministic_topo():
    p = PlanningModule()
    _plan(p)
    rec = p.sequence("p1", [("a", "b"), ("b", "c")], 3)
    assert rec.revision == 1
    assert rec.topo_order == ("a", "b", "c")
    assert rec.verify("p1", (("a", "b"), ("b", "c")), 1, 3)
    assert not rec.verify("p1", (("a", "b"),), 1, 3)
    assert p.sequence_history("p1") == (rec,)
    assert p.topo_order("p1") == ("a", "b", "c")
    # No dependencies: declared order.
    p2 = PlanningModule()
    _plan(p2, plan="q")
    rec2 = p2.sequence("q", [], 3)
    assert rec2.topo_order == ("a", "b", "c")
    # Diamond: deterministic, declared-order tie-break.
    p3 = PlanningModule()
    p3.goal("g", "d", 1)
    p3.decompose("g", "r", [("x", "dx"), ("y", "dy"), ("z", "dz"),
                            ("w", "dw")], 2)
    rec3 = p3.sequence("r", [("x", "z"), ("y", "z"), ("z", "w")], 3)
    assert rec3.topo_order == ("x", "y", "z", "w")
    # Cross-instance determinism.
    p4 = PlanningModule()
    _plan(p4)
    rec4 = p4.sequence("p1", [("a", "b"), ("b", "c")], 3)
    assert rec4.digest == rec.digest


def test_sequence_bad_dependencies():
    p = PlanningModule()
    _plan(p)
    cases = [
        ([("a", "nope")], pm.UnknownStepError),
        ([("nope", "a")], pm.UnknownStepError),
        ([("a", "a")], pm.BadDependencyError),
        ([("a", "b"), ("a", "b")], pm.BadDependencyError),
        ([("a", "b"), ("b", "a")], pm.CyclicDependencyError),
        ([("a", "b"), ("b", "c"), ("c", "a")], pm.CyclicDependencyError),
        ([("a",)], pm.BadDependencyError),
        ("nope", pm.BadDependencyError),
    ]
    seq = 3
    for deps, exc in cases:
        with pytest.raises(exc):
            p.sequence("p1", deps, seq)
        seq += 1
    with pytest.raises(pm.UnknownPlanError):
        p.sequence("missing", [], seq)


def test_sequence_revision_and_resequence_after_execution_refused():
    p = PlanningModule()
    _plan(p)
    r1 = p.sequence("p1", [("a", "b")], 3)
    r2 = p.sequence("p1", [("a", "b"), ("b", "c")], 4)
    assert (r1.revision, r2.revision) == (1, 2)
    assert r2.topo_order == ("a", "b", "c")
    p.execute("p1", "a", "done", 5)
    with pytest.raises(pm.PlanExecutingError):
        p.sequence("p1", [("a", "b")], 6)
    # Latest sequence still revision 2.
    assert p.sequence_history("p1")[-1].revision == 2


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


def test_execute_roundtrip_and_minted_ids():
    p = PlanningModule()
    _plan(p)
    p.sequence("p1", [("a", "b"), ("b", "c")], 3)
    e1 = p.execute("p1", "a", "done", 4)
    assert e1.exec_id == "exec-1"
    e2 = p.execute("p1", "b", "done", 5)
    assert e2.exec_id == "exec-2"
    assert e2.verify("p1", "b", "done", 5)
    assert not e2.verify("p1", "b", "failed", 5)
    assert p.executions("p1") == (e1, e2)


def test_execute_out_of_order_and_bad_inputs():
    p = PlanningModule()
    _plan(p)
    p.sequence("p1", [("a", "b"), ("b", "c")], 3)
    with pytest.raises(pm.OutOfOrderError):
        p.execute("p1", "c", "done", 4)   # predecessors a,b not done
    with pytest.raises(pm.OutOfOrderError):
        p.execute("p1", "b", "done", 5)   # predecessor a not done
    p.execute("p1", "a", "done", 6)
    with pytest.raises(pm.OutOfOrderError):
        p.execute("p1", "c", "done", 7)   # b still pending
    with pytest.raises(pm.BadOutcomeError):
        p.execute("p1", "a", "finished", 8)
    with pytest.raises(pm.BadOutcomeError):
        p.execute("p1", "a", None, 9)
    with pytest.raises(pm.UnknownPlanError):
        p.execute("missing", "a", "done", 10)
    with pytest.raises(pm.UnknownStepError):
        p.execute("p1", "nope", "done", 11)
    rejected = [r for r in p.audit_log() if r["kind"] == "rejected"]
    assert [r["seq"] for r in rejected] == [4, 5, 7, 8, 9, 10, 11]


def test_execute_retry_after_failure():
    p = PlanningModule()
    _plan(p)
    p.sequence("p1", [("a", "b")], 3)
    p.execute("p1", "a", "failed", 4)
    # Failed step "a" is eligible again; "c" has no dependencies so it
    # was eligible all along; successor "b" stays blocked.
    assert p.next_steps("p1", 4).next_step_ids == ("a", "c")
    e2 = p.execute("p1", "a", "done", 5)
    assert e2.exec_id == "exec-2"
    # "b" unblocked now; "c" (no deps) still eligible.
    assert p.next_steps("p1", 5).next_step_ids == ("b", "c")
    state = p.plan_state("p1", 5)
    by_id = {s.step_id: s for s in state.steps}
    assert by_id["a"].status == "done" and by_id["a"].executions == 2


# ---------------------------------------------------------------------------
# views & seq discipline
# ---------------------------------------------------------------------------


def test_views_are_pure_reads():
    p = PlanningModule()
    _plan(p)
    p.sequence("p1", [("a", "b")], 3)
    rows_before = len(p.audit_log())
    s1 = p.plan_state("p1", 3)
    s2 = p.plan_state("p1", 3)   # same seq twice: pure read
    n1 = p.next_steps("p1", 3)
    n2 = p.next_steps("p1", 3)
    assert s1 == s2 and n1 == n2
    assert n1.next_step_ids == ("a", "c")  # c has no dependencies
    assert s1.topo_order == ("a", "b", "c")
    assert all(s.status == "pending" for s in s1.steps)
    assert len(p.audit_log()) == rows_before  # no audit rows, no seq use
    with pytest.raises(pm.UnknownPlanError):
        p.plan_state("missing", 3)


def test_seq_ordering_and_rewind_bare():
    p = PlanningModule()
    p.goal("g", "d", 1)
    with pytest.raises(pm.SeqOrderError):   # rewind: bare, no audit row
        p.goal("g2", "d", 1)
    with pytest.raises(pm.SeqOrderError):
        p.goal("g2", "d", 0)
    for bad in (True, "2", 2.0, None, -1):
        with pytest.raises(pm.SeqOrderError):
            p.goal("g2", "d", bad)
    assert not [r for r in p.audit_log() if r["kind"] == "rejected"]
    p.goal("g2", "d", 2)  # last good seq still 1


# ---------------------------------------------------------------------------
# audit & main
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban_and_bad_kind():
    p = PlanningModule()
    p.goal("launch", "super secret plan text", 1)
    rows = p.audit_log()
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "planning-module.v1"
    assert rows[0]["kind"] == "goal-registered"
    assert rows[0]["seq"] == 1
    detail = rows[0]["detail"]
    assert "super secret plan text" not in str(detail.values())
    assert detail["goal_id"] == "launch"
    # _plan hardcodes seqs 1/2; here seq 1 is taken, so book inline.
    p.goal("g2", "d2", 2)
    p.decompose("g2", "p2", [("a", "da"), ("b", "db")], 3)
    kinds = [r["kind"] for r in p.audit_log()]
    assert kinds[:3] == ["goal-registered", "goal-registered", "decomposed"]
    with pytest.raises(pm.AuditKindError):
        pm.planning_module_audit_event("bogus", {}, 1)
    with pytest.raises(pm.AuditKindError):
        pm.planning_module_audit_event("goal-registered",
                                       {"description": "leak"}, 1)
    with pytest.raises(pm.SeqOrderError):  # seq checked before kind detail
        pm.planning_module_audit_event("goal-registered", {}, "bad-seq")


def test_main_subprocess():
    r = subprocess.run([sys.executable, _module_path()],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == ("planning-module OK: goal, decompose, "
                                "sequence, execute, audit")
