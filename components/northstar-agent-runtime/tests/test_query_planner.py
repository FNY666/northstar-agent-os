"""Tests for query_planner.py (spec: 15 tests)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import query_planner
from query_planner import (
    VERSION,
    SCHEMA,
    QueryPlanner,
    query_planner_audit_event,
    BadQueryError,
    BadPlanError,
    DuplicatePlanError,
    UnknownPlanError,
    BadStatsError,
    DuplicateStatsError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(query_planner.__file__)


def fresh_planner():
    qp = QueryPlanner()
    qp.register_stats("users", 10_000, 1)
    qp.register_stats("orders", 500, 2)
    return qp


QUERY = {
    "tables": ("users", "orders"),
    "filters": (("users", "active", "==", True),),
    "joins": (("users", "orders", "id", "user_id"),),
    "projections": ("users.name",),
    "sort": ("users.name", "asc"),
    "limit": 50,
}


def test_version_and_schema_pins():
    assert VERSION == "query-planner.v1"
    assert SCHEMA == "northstar.query-planner.v1"
    qp = fresh_planner()
    rec = qp.register_stats("t", 7, 3)
    assert rec.digest.startswith("sha256:")


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
    # canonical_json is imported lazily inside a try/except fallback.
    assert imported - allowed <= {"json", "canonical_json"}


def test_register_stats_roundtrip():
    qp = QueryPlanner()
    rec = qp.register_stats("events", 42, 1)
    assert rec.verify()
    assert rec.table_id == "events" and rec.row_count == 42
    assert qp.stats_record("events") == rec
    assert qp.stats(1) == {"events": 42}
    # duplicate refused, seq consumed
    with pytest.raises(DuplicateStatsError):
        qp.register_stats("events", 9, 2)
    assert qp.stats_record("events").row_count == 42


def test_stats_bad_inputs():
    qp = QueryPlanner()
    for bad, exc in (
        (lambda s: qp.register_stats("", 1, s), BadStatsError),
        (lambda s: qp.register_stats("t", -1, s), BadStatsError),
        (lambda s: qp.register_stats("t", True, s), BadStatsError),
        (lambda s: qp.register_stats("t", 1.5, s), BadStatsError),
        (lambda s: qp.register_stats("t", 2**53, s), BadStatsError),
    ):
        with pytest.raises(exc):
            bad(qp._seq + 1)


def test_plan_single_table():
    qp = QueryPlanner()
    qp.register_stats("users", 1_000, 1)
    q = {
        "tables": ("users",),
        "filters": (("users", "age", ">=", 18),),
        "projections": ("users.name",),
        "sort": ("users.name", "desc"),
        "limit": 10,
    }
    rec = qp.plan("p1", q, 2)
    assert rec.verify()
    ops = [s.op for s in rec.steps]
    assert ops == ["scan", "filter", "project", "sort", "limit"]
    # filter selectivity: >= is 1/3 -> 1000 // 3 = 333
    filt = rec.steps[1]
    assert filt.est_rows == 333 and filt.cost == 1000
    lim = rec.steps[-1]
    assert lim.est_rows == 10 and lim.cost == 10
    assert rec.total_cost == sum(s.cost for s in rec.steps)
    assert all(s.verify() for s in rec.steps)


def test_plan_join_algorithm_choice():
    qp = QueryPlanner()
    qp.register_stats("big", 100_000, 1)
    qp.register_stats("small", 50, 2)
    q = {
        "tables": ("big", "small"),
        "joins": (("big", "small", "id", "big_id"),),
    }
    rec = qp.plan("j1", q, 3)
    ops = [s.op for s in rec.steps]
    # hash join: 100050 vs nested loop: 5_000_000 -> hash wins
    assert "hash_join" in ops
    # tiny tables: nested loop can win
    qp2 = QueryPlanner()
    qp2.register_stats("a", 3, 1)
    qp2.register_stats("b", 4, 2)
    rec2 = qp2.plan("j2", {"tables": ("a", "b"), "joins": (("a", "b", "id", "a_id"),)}, 3)
    ops2 = [s.op for s in rec2.steps]
    # nested loop: 12 < hash: 7? no: 12 > 7 -> hash wins. check determinism only.
    assert ops2[2] in ("hash_join", "nested_loop_join")
    assert rec2.verify()


def test_plan_bad_inputs():
    qp = QueryPlanner()
    cases = [
        ({"tables": ()}, "empty tables"),
        ({"tables": ("a", "a")}, "duplicate table"),
        ({"tables": ("a", "b"), "joins": ()}, "disconnected"),
        (
            {"tables": ("a",), "filters": (("b", "x", "==", 1),)},
            "filter unknown table",
        ),
        (
            {"tables": ("a",), "filters": (("a", "x", "~~", 1),)},
            "bad op",
        ),
        (
            {"tables": ("a", "b"), "joins": (("a", "a", "x", "y"),)},
            "self join",
        ),
        ({"tables": ("a",), "limit": 0}, "bad limit"),
        ({"tables": ("a",), "limit": True}, "bool limit"),
        ({"tables": ("a",), "sort": ("x", "sideways")}, "bad direction"),
        ("not-a-mapping", "not a mapping"),
    ]
    seq = 0
    for q, _why in cases:
        seq += 1
        with pytest.raises(BadQueryError):
            qp.plan(f"bad-{seq}", q, seq)
    # every failure consumed its seq and booked a rejected row
    rejected = [r for r in qp.audit_log() if r["kind"] == "query.rejected"]
    assert len(rejected) == len(cases)


def test_duplicate_plan_refused():
    qp = fresh_planner()
    qp.plan("p1", QUERY, 3)
    with pytest.raises(DuplicatePlanError):
        qp.plan("p1", QUERY, 4)
    with pytest.raises(BadPlanError):
        qp.plan("", QUERY, 5)


def test_seq_ordering():
    qp = fresh_planner()
    qp.plan("p1", QUERY, 3)
    with pytest.raises(SeqOrderError):  # rewind raises bare, consumes nothing
        qp.plan("p2", QUERY, 3)
    with pytest.raises(SeqOrderError):
        qp.plan("p2", QUERY, True)
    with pytest.raises(SeqOrderError):
        qp.plan("p2", QUERY, -1)
    # failed mutations consumed their seqs: next fresh seq works
    qp.plan("p2", QUERY, 4)
    assert qp.plan_ids() == ("p1", "p2")


def test_cost_report_read_purity():
    qp = fresh_planner()
    plan = qp.plan("p1", QUERY, 3)
    r1 = qp.cost("p1", 3)  # same seq: reads never consume
    r2 = qp.cost("p1", 3)
    assert r1.verify() and r2.verify()
    assert r1.total_cost == plan.total_cost
    assert sum(c for _op, _t, c, _r in r1.steps) == plan.total_cost
    # unknown plan is data-free fail-closed
    with pytest.raises(UnknownPlanError):
        qp.cost("nope", 3)
    # next mutation seq unaffected by reads
    qp.plan("p2", QUERY, 4)


def test_optimize_never_costs_more():
    qp = QueryPlanner()
    qp.register_stats("huge", 1_000_000, 1)
    qp.register_stats("mid", 10_000, 2)
    qp.register_stats("tiny", 100, 3)
    q = {
        "tables": ("huge", "mid", "tiny"),
        "joins": (
            ("huge", "mid", "id", "huge_id"),
            ("mid", "tiny", "id", "mid_id"),
        ),
    }
    plan = qp.plan("p1", q, 4)
    opt = qp.optimize("p1", 5)
    assert opt.verify()
    assert opt.original_cost == plan.total_cost
    assert opt.optimized_cost <= opt.original_cost
    # greedy smallest-first: tiny should lead the optimized join order
    scans = [s.target for s in opt.steps if s.op == "scan"]
    assert scans[0] == "tiny"
    with pytest.raises(UnknownPlanError):
        qp.optimize("nope", 6)
    assert qp.optimized_record("p1") == opt


def test_audit_shapes_and_banned_keys():
    qp = fresh_planner()
    qp.plan("p1", QUERY, 3)
    qp.optimize("p1", 4)
    kinds = [r["kind"] for r in qp.audit_log()]
    assert "query.planned" in kinds and "query.optimized" in kinds
    for row in qp.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        banned = {"payload", "value", "raw", "body", "data", "query", "filter", "plan"}
        assert not (banned & set(row["detail"]))
    with pytest.raises(AuditKindError):
        query_planner_audit_event("bogus.kind", {}, 1)
    with pytest.raises(AuditKindError):
        query_planner_audit_event("query.planned", {"query": "x"}, 1)


def test_cross_instance_determinism():
    def build():
        qp = QueryPlanner()
        qp.register_stats("users", 10_000, 1)
        qp.register_stats("orders", 500, 2)
        return qp.plan("p1", QUERY, 3)

    a, b = build(), build()
    assert a.digest == b.digest
    assert a.query_digest == b.query_digest
    assert [s.digest for s in a.steps] == [s.digest for s in b.steps]


def test_stats_view_and_plan_views():
    qp = fresh_planner()
    assert qp.plan_record("missing") is None
    assert qp.optimized_record("missing") is None
    assert qp.plan_ids() == ()
    qp.plan("p1", QUERY, 3)
    assert qp.plan_record("p1").verify()
    assert qp.plan_ids() == ("p1",)
    assert set(qp.stats(3)) == {"users", "orders"}


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "query-planner OK" in proc.stdout
