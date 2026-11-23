"""Tests for goal_misgeneralization.py (goal-misgeneralization detection / correction bookkeeping ledger)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import goal_misgeneralization as gm
from goal_misgeneralization import (
    GoalMisgeneralization,
    goal_misgeneralization_audit_event,
    GOAL_MISGENERALIZATION_VERSION,
    GOAL_MISGENERALIZATION_SCHEMA,
    AUDIT_SCHEMA,
    KIND_GOAL_DECLARED,
    KIND_OBSERVED,
    KIND_DETECTED,
    KIND_CORRECTED,
    KIND_TESTED,
    KIND_REJECTED,
    GoalMisgeneralizationError,
    BadGoalError,
    DuplicateGoalError,
    UnknownGoalError,
    BadDigestError,
    BadStrategyError,
    BadVerdictError,
    BadThresholdError,
    NoObservationsError,
    NoDetectionError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(gm.__file__)
INTENDED = "sha256:" + "a" * 64
OFF_GOAL = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64


def fresh():
    return GoalMisgeneralization()


def ledger_with_goal():
    m = fresh()
    m.declare_goal("coinrun", INTENDED, 1)
    return m


def ledger_with_observations():
    m = ledger_with_goal()
    for i, d in enumerate((INTENDED, INTENDED, INTENDED, OFF_GOAL), start=2):
        m.observe("coinrun", d, d, i)
    return m


# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert GOAL_MISGENERALIZATION_VERSION == "goal-misgeneralization.v1"
    assert GOAL_MISGENERALIZATION_SCHEMA == "northstar.goal-misgeneralization.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "fractions",
        "typing",
        "json",
        "canonical_json",
        "__future__",
    }
    assert imported <= allowed, f"non-stdlib imports: {imported - allowed}"


def test_declare_goal_roundtrip_and_verify():
    m = fresh()
    rec = m.declare_goal("coinrun", INTENDED, 1)
    assert rec.goal_id == "coinrun"
    assert rec.intended_digest == INTENDED
    assert rec.seq == 1
    assert rec.schema == GOAL_MISGENERALIZATION_SCHEMA
    assert rec.verify()
    assert m.goal_record("coinrun", 2) == rec
    assert m.goal_record("nope", 2) is None
    assert m.goal_ids(2) == ("coinrun",)


def test_declare_goal_bad_inputs_with_seq_burn():
    m = fresh()
    rejected_before = len(m.audit_log())
    for bad in ("", 123, None, True, "x" * 257):
        with pytest.raises((BadGoalError, GoalMisgeneralizationError)):
            m.declare_goal(bad, INTENDED, len(m.audit_log()) + 1)
    for bad_digest in ("", "a" * 64, "md5:" + "a" * 32, 123, True):
        with pytest.raises(BadDigestError):
            m.declare_goal(f"g-{len(m.audit_log())}", bad_digest, len(m.audit_log()) + 1)
    # failed mutations consume seq: 10 rejected seqs burned, ledger seq == 10
    assert m.stats(0)["last_seq"] == 10
    assert len(m.audit_log()) == rejected_before + 10
    assert all(e["kind"] == KIND_REJECTED for e in m.audit_log())
    # duplicate after valid declare
    m.declare_goal("coinrun", INTENDED, 11)
    with pytest.raises(DuplicateGoalError):
        m.declare_goal("coinrun", INTENDED, 12)
    assert m.stats(0)["last_seq"] == 12


def test_observe_roundtrip_and_verify():
    m = ledger_with_goal()
    obs = m.observe("coinrun", INTENDED, INTENDED, 2, context_digest=OTHER)
    assert obs.observation_id == "obs-1"
    assert obs.goal_id == "coinrun"
    assert obs.context_digest == OTHER
    assert obs.verify()
    assert m.observations_for("coinrun", 3) == (obs,)
    assert m.observations_for("nope", 3) == ()


def test_observe_bad_inputs():
    m = fresh()
    with pytest.raises(UnknownGoalError):
        m.observe("ghost", INTENDED, INTENDED, 1)
    m.declare_goal("coinrun", INTENDED, 2)
    for bad in ("", "nope-digest", 123, True):
        with pytest.raises(BadDigestError):
            m.observe("coinrun", bad, INTENDED, m.stats(0)["last_seq"] + 1)
        with pytest.raises(BadDigestError):
            m.observe("coinrun", INTENDED, bad, m.stats(0)["last_seq"] + 1)
    assert m.observations_for("coinrun", 1) == ()


def test_detect_clean_as_data():
    m = ledger_with_goal()
    for i in (2, 3):
        m.observe("coinrun", INTENDED, INTENDED, i)
    rep = m.detect("coinrun", 4)
    assert rep.report_id == "rep-1"
    assert rep.divergent == 0 and rep.total == 2
    assert rep.divergence_text == "0/1"  # Fraction normalizes 0/2 -> 0/1; exact either way
    assert rep.misgeneralized is False
    assert rep.verify()
    assert m.detection_report("rep-1", 5) == rep
    assert m.detection_report("rep-9", 5) is None
    assert m.reports_for("coinrun", 5) == (rep,)


def test_detect_divergence_exact_fraction_and_threshold():
    m = ledger_with_observations()  # 3 on-goal, 1 divergent
    rep = m.detect("coinrun", 6)
    assert rep.divergent == 1 and rep.total == 4
    assert rep.divergence_text == "1/4"
    assert rep.misgeneralized is False  # 0.25 < 0.5
    assert rep.verify()
    rep2 = m.detect("coinrun", 7, threshold=0.25)
    assert rep2.misgeneralized is True  # 0.25 >= 0.25
    assert rep2.divergence_text == "1/4"
    rep3 = m.detect("coinrun", 8, threshold=1)
    assert rep3.misgeneralized is False


def test_detect_no_observations_fail_closed():
    m = ledger_with_goal()
    with pytest.raises(NoObservationsError):
        m.detect("coinrun", 2)
    with pytest.raises(UnknownGoalError):
        m.detect("ghost", 3)
    for bad in (0, -0.5, 1.5, True, "half", float("nan"), float("inf")):
        with pytest.raises(BadThresholdError):
            m.detect("coinrun", m.stats(0)["last_seq"] + 1, threshold=bad)


def test_correct_roundtrip_and_strategy_vocabulary():
    m = ledger_with_observations()
    m.detect("coinrun", 6)
    cor = m.correct("coinrun", 7, "reward-reshape")
    assert cor.correction_id == "cor-1"
    assert cor.report_id == "rep-1"
    assert cor.goal_id == "coinrun"
    assert cor.strategy == "reward-reshape"
    assert cor.verify()
    assert m.corrections_for("coinrun", 8) == (cor,)
    assert m.corrections_for("nope", 8) == ()
    # repeat corrections allowed (escalation chain)
    cor2 = m.correct("coinrun", 8, "human-review")
    assert cor2.correction_id == "cor-2" and cor2.report_id == "rep-1"
    assert m.stats(0)["corrections"] == 2


def test_correct_without_detection_refused():
    m = ledger_with_observations()  # last_seq == 5
    with pytest.raises(NoDetectionError):
        m.correct("coinrun", 6, "retrain")
    with pytest.raises(UnknownGoalError):
        m.correct("ghost", 7, "retrain")
    m2 = ledger_with_goal()
    with pytest.raises(NoObservationsError):
        m2.detect("coinrun", 2)
    # bad strategy vocabulary (needs a detection booked first)
    m.detect("coinrun", 8)  # last_seq == 8
    for bad in ("restart", "", 123, True, "retrain "):
        with pytest.raises(BadStrategyError):
            m.correct("coinrun", m.stats(0)["last_seq"] + 1, bad)
    # all six pinned strategies accepted, each on a fresh ledger
    for i, s in enumerate(("retrain", "reward-reshape", "constraint-add", "monitor", "rollback", "human-review")):
        l = ledger_with_observations()
        l.detect("coinrun", 6)
        assert l.correct("coinrun", 7, s).strategy == s


def test_test_probe_roundtrip_and_verdict_vocabulary():
    m = ledger_with_goal()
    tst = m.test("coinrun", 2, scenario_digest=OFF_GOAL, verdict="breaks")
    assert tst.test_id == "tst-1"
    assert tst.scenario_digest == OFF_GOAL
    assert tst.verdict == "breaks"
    assert tst.verify()
    assert m.tests_for("coinrun", 3) == (tst,)
    # scenario digest optional, default verdict inconclusive
    tst2 = m.test("coinrun", 3)
    assert tst2.verdict == "inconclusive" and tst2.scenario_digest == ""
    assert tst2.verify()
    with pytest.raises(UnknownGoalError):
        m.test("ghost", 4)
    for bad in ("passes", "", 123, True):
        with pytest.raises(BadVerdictError):
            m.test("coinrun", m.stats(0)["last_seq"] + 1, verdict=bad)
    with pytest.raises(BadDigestError):
        m.test("coinrun", m.stats(0)["last_seq"] + 1, scenario_digest="not-a-digest")


def test_seq_discipline():
    m = ledger_with_goal()
    # rewind: raises bare, consumes nothing, books no rejected row
    with pytest.raises(SeqOrderError):
        m.observe("coinrun", INTENDED, INTENDED, 1)
    assert m.stats(0)["last_seq"] == 1
    assert m.audit_log()[-1]["kind"] == KIND_GOAL_DECLARED
    # malformed seqs
    for bad in (True, "2", 2.0, None, -1):
        with pytest.raises(SeqOrderError):
            m.observe("coinrun", INTENDED, INTENDED, bad)
    assert m.stats(0)["last_seq"] == 1
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(BadDigestError):
        m.observe("coinrun", "bad", INTENDED, 2)
    assert m.stats(0)["last_seq"] == 2
    assert m.audit_log()[-1]["kind"] == KIND_REJECTED
    # pure-read views validate seq shape but never consume
    m.observe("coinrun", INTENDED, INTENDED, 3)
    m.goal_ids(3)  # same seq as last mutation: fine for reads
    m.stats(3)
    assert m.stats(0)["last_seq"] == 3
    with pytest.raises(SeqOrderError):
        m.goal_ids(True)


def test_audit_shapes_and_leak_ban():
    m = ledger_with_observations()
    m.detect("coinrun", 6)
    m.correct("coinrun", 7, "monitor")
    m.test("coinrun", 8, scenario_digest=OTHER, verdict="holds")
    log = m.audit_log()
    kinds = [e["kind"] for e in log]
    assert kinds == [
        KIND_GOAL_DECLARED,
        KIND_OBSERVED,
        KIND_OBSERVED,
        KIND_OBSERVED,
        KIND_OBSERVED,
        KIND_DETECTED,
        KIND_CORRECTED,
        KIND_TESTED,
    ]
    for e in log:
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == "goal-misgeneralization"
        detail = e["detail"]
        for banned in (
            "intent",
            "behavior",
            "outcome",
            "scenario",
            "text",
            "content",
            "payload",
            "raw",
        ):
            assert banned not in detail, f"banned key {banned!r} in audit detail"
    # builder rejects unknown kinds and banned keys
    with pytest.raises(AuditKindError):
        goal_misgeneralization_audit_event("goal-misgeneralization.nope", 1)
    with pytest.raises(AuditKindError):
        goal_misgeneralization_audit_event(KIND_DETECTED, 1, behavior="oops")
    ev = goal_misgeneralization_audit_event(KIND_TESTED, 1, test_id="tst-1", verdict="holds")
    assert ev["kind"] == KIND_TESTED and ev["seq"] == 1
    assert ev["digest"].startswith("sha256:")


def test_views_stats_and_cross_instance_determinism():
    m = ledger_with_observations()
    rep = m.detect("coinrun", 6)
    stats = m.stats(7)
    assert stats["goals"] == 1
    assert stats["observations"] == 4
    assert stats["reports"] == 1
    assert stats["corrections"] == 0
    assert stats["tests"] == 0
    assert stats["misgeneralized_goals"] == 0
    # same insert sequence on a fresh instance: byte-identical digests
    m2 = ledger_with_observations()
    rep2 = m2.detect("coinrun", 6)
    assert rep.digest == rep2.digest
    assert [o.digest for o in m.observations_for("coinrun", 7)] == [
        o.digest for o in m2.observations_for("coinrun", 7)
    ]
    # tamper rejection
    bad = rep.__class__(**{**rep.__dict__})
    object.__setattr__(bad, "divergent", 99)
    assert bad.verify() is False
    # main() subprocess self-check
    r = subprocess.run(
        [sys.executable, str(MODULE)], capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == (
        "goal-misgeneralization OK: declare, observe, detect, correct, test, pins"
    )


# ---------------------------------------------------------------------------
# evaluate() -- derived assessment posture (pure read)
# ---------------------------------------------------------------------------


def test_evaluate_untested_and_holding():
    m = ledger_with_goal()
    rep = m.evaluate("coinrun", 2)
    assert rep.posture == gm.POSTURE_UNTESTED
    assert rep.verify() is True
    assert rep.n_reports == 0
    assert rep.latest_divergence == "0/0"
    # all-clean observations -> holding
    m2 = ledger_with_observations()
    r2 = m2.detect("coinrun", 6, threshold=0.5)  # 1/4 divergent < 0.5
    assert r2.misgeneralized is False
    ev = m2.evaluate("coinrun", 7)
    assert ev.posture == gm.POSTURE_HOLDING
    assert ev.verify() is True
    assert ev.n_observations == 4
    assert ev.n_reports == 1
    assert ev.n_misgeneralized == 0
    assert ev.latest_divergence == "1/4"
    # frozen record: attribute assignment is refused
    with pytest.raises(Exception):
        rep.posture = "holding"  # type: ignore


def test_evaluate_misgeneralized_then_corrected():
    m = ledger_with_observations()
    m.detect("coinrun", 6, threshold=0.25)  # 1/4 >= 0.25 -> misgeneralized
    ev = m.evaluate("coinrun", 7)
    assert ev.posture == gm.POSTURE_MISGENERALIZED
    assert ev.n_misgeneralized == 1
    assert ev.verify() is True
    # booking a correction flips posture to corrected (no proof it worked)
    cor = m.correct("coinrun", 8, "reward-reshape")
    assert cor.verify()
    ev2 = m.evaluate("coinrun", 9)
    assert ev2.posture == gm.POSTURE_CORRECTED
    assert ev2.n_corrections == 1
    assert ev2.verify() is True


def test_evaluate_breaks_outranks_and_unknown_goal():
    m = ledger_with_observations()
    m.detect("coinrun", 6, threshold=0.25)  # misgeneralized
    m.correct("coinrun", 7, "monitor")
    # OOD probe verdict "breaks" dominates as data
    m.test("coinrun", 8, scenario_digest=OFF_GOAL, verdict="breaks")
    ev = m.evaluate("coinrun", 9)
    assert ev.posture == gm.POSTURE_BREAKS
    assert ev.n_tests == 1
    assert ev.verify() is True
    # unknown goal is fail-closed
    with pytest.raises(gm.UnknownGoalError):
        m.evaluate("nope", 10)
    # malformed seqs rejected on the pure read (shape check, no consumption);
    # note: 0/-1 are shape-valid ints here (no rewind semantics on reads)
    for bad in (1.5, True, None, "9"):
        with pytest.raises(gm.SeqOrderError):
            m.evaluate("coinrun", bad)


def test_evaluate_read_purity():
    m = ledger_with_observations()
    m.detect("coinrun", 6)
    before = len(m.audit_log())
    seq_before = m.stats(7)["last_seq"]
    e1 = m.evaluate("coinrun", 100)
    e2 = m.evaluate("coinrun", 100)  # same seq twice: no consumption
    assert e1 == e2
    assert e1.digest == e2.digest
    assert len(m.audit_log()) == before  # no audit row
    assert m.stats(101)["last_seq"] == seq_before  # seq untouched
    # cross-instance determinism
    m2 = ledger_with_observations()
    m2.detect("coinrun", 6)
    assert m2.evaluate("coinrun", 100).digest == e1.digest
    # tamper breaks verify() (posture is "holding" here, so flip it)
    bad = e1.__class__(**{**e1.__dict__})
    object.__setattr__(bad, "posture", "breaks")
    assert bad.verify() is False


def test_evaluate_posture_vocabulary_and_schema():
    assert gm.POSTURE_UNTESTED in gm._POSTURES
    assert gm.POSTURE_BREAKS in gm._POSTURES
    assert gm.POSTURE_MISGENERALIZED in gm._POSTURES
    assert gm.POSTURE_CORRECTED in gm._POSTURES
    assert gm.POSTURE_HOLDING in gm._POSTURES
    m = ledger_with_observations()
    m.detect("coinrun", 6)
    ev = m.evaluate("coinrun", 7)
    assert ev.schema == gm.GOAL_MISGENERALIZATION_SCHEMA
    assert ev.posture in gm._POSTURES
