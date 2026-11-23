"""15 targeted tests for the red_team engagement ledger."""

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "red_team.py"


def _load():
    name = "red_team_under_test"
    spec = importlib.util.spec_from_file_location(name, str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    # Frozen dataclasses need the module registered before exec.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mod():
    return _load()


def _pin(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# 1 --------------------------------------------------------------------------
def test_version_and_schema_pins(mod):
    assert mod.RED_TEAM_VERSION == "red-team.v1"
    assert mod.SCHEMA_PIN == "northstar.red-team.v1"
    assert mod.ENGAGEMENT_TYPES == (
        "tabletop",
        "purple-team",
        "adversarial-simulation",
        "continuous",
    )
    assert mod.PHASES == (
        "kickoff",
        "fieldwork",
        "debrief",
        "remediation-validation",
    )
    assert mod.OUTCOMES == ("completed", "blocked", "deferred", "not-attempted")
    assert mod.AUDIT_KINDS == ("planned", "executed", "reported", "rejected")


# 2 --------------------------------------------------------------------------
def test_stdlib_only_ast(mod):
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module in allowed, node.module


# 3 --------------------------------------------------------------------------
def test_plan_roundtrip_and_verify(mod):
    rt = mod.RedTeam()
    rec = rt.plan(
        "eng-1",
        1,
        engagement_type="purple-team",
        scope_digest=_pin("scope"),
        objective_digest=_pin("objective"),
    )
    assert rec.engagement_id == "eng-1"
    assert rec.engagement_type == "purple-team"
    assert rec.verify()
    assert rt.engagement_record("eng-1", 2) == rec
    assert rt.engagement_record("eng-1", 3).verify()


# 4 --------------------------------------------------------------------------
def test_plan_bad_inputs_burn_seq_and_book_rejected(mod):
    rt = mod.RedTeam()
    bad_calls = [
        lambda s: rt.plan("", s),
        lambda s: rt.plan(123, s),
        lambda s: rt.plan("x" * 129, s),
        lambda s: rt.plan("eng-bad", s, engagement_type="red-vs-blue"),
        lambda s: rt.plan("eng-bad", s, engagement_type=""),
        lambda s: rt.plan("eng-bad", s, scope_digest="not-a-pin"),
        lambda s: rt.plan("eng-bad", s, objective_digest="sha256:zzz"),
    ]
    rejected_before = sum(
        1 for row in rt.audit_log(1) if row["kind"] == "rejected"
    )
    seq = 2
    for call in bad_calls:
        with pytest.raises(mod.RedTeamError):
            call(seq)
        seq += 1
    # One extra bad seq-consumed attempt: duplicates also burn.
    rt.plan("eng-dup", seq, engagement_type="tabletop")
    seq += 1
    with pytest.raises(mod.DuplicateEngagementError):
        rt.plan("eng-dup", seq, engagement_type="tabletop")
    rejected = [row for row in rt.audit_log(seq + 1) if row["kind"] == "rejected"]
    assert len(rejected) - rejected_before == len(bad_calls) + 1
    assert all(row["schema"] == "audit.ndjson/1" for row in rejected)


# 5 --------------------------------------------------------------------------
def test_full_engagement_type_vocabulary(mod):
    rt = mod.RedTeam()
    seq = 1
    for i, etype in enumerate(mod.ENGAGEMENT_TYPES):
        rec = rt.plan(f"eng-vocab-{i}", seq, engagement_type=etype)
        assert rec.engagement_type == etype
        seq += 1
    assert rt.engagement_ids(seq) == tuple(f"eng-vocab-{i}" for i in range(4))


# 6 --------------------------------------------------------------------------
def test_execute_roundtrip_minted_ids_and_verify(mod):
    rt = mod.RedTeam()
    rt.plan("eng-x", 1)
    e1 = rt.execute("eng-x", 2, phase="kickoff", outcome="completed",
                    evidence_digest=_pin("evidence-1"))
    e2 = rt.execute("eng-x", 3, phase="fieldwork", outcome="blocked")
    assert e1.execution_id == "exe-1"
    assert e2.execution_id == "exe-2"
    assert e1.verify() and e2.verify()
    assert rt.execution_record("exe-1", 4) == e1
    assert rt.executions_for("eng-x", 5) == ("exe-1", "exe-2")


# 7 --------------------------------------------------------------------------
def test_execute_bad_inputs_burn_seq(mod):
    rt = mod.RedTeam()
    rt.plan("eng-y", 1)
    bad_calls = [
        lambda s: rt.execute("unknown-eng", s),
        lambda s: rt.execute("", s),
        lambda s: rt.execute("eng-y", s, phase="exploit"),
        lambda s: rt.execute("eng-y", s, phase=""),
        lambda s: rt.execute("eng-y", s, outcome="breached"),
        lambda s: rt.execute("eng-y", s, outcome=""),
        lambda s: rt.execute("eng-y", s, evidence_digest="raw-evidence"),
    ]
    rejected_before = sum(
        1 for row in rt.audit_log(2) if row["kind"] == "rejected"
    )
    seq = 3
    with pytest.raises(mod.UnknownEngagementError):
        bad_calls[0](seq)
    seq += 1
    for call in bad_calls[1:]:
        with pytest.raises(mod.RedTeamError):
            call(seq)
        seq += 1
    rejected = [row for row in rt.audit_log(seq) if row["kind"] == "rejected"]
    assert len(rejected) - rejected_before == len(bad_calls)
    assert rt.stats(seq + 1)["executions"] == 0


# 8 --------------------------------------------------------------------------
def test_execute_chain_and_full_phase_vocabulary(mod):
    rt = mod.RedTeam()
    rt.plan("eng-chain", 1, engagement_type="adversarial-simulation")
    seq = 2
    for phase in mod.PHASES:
        for outcome in mod.OUTCOMES:
            rt.execute("eng-chain", seq, phase=phase, outcome=outcome)
            seq += 1
    ids = rt.executions_for("eng-chain", seq)
    assert len(ids) == len(mod.PHASES) * len(mod.OUTCOMES)
    assert ids == tuple(f"exe-{i + 1}" for i in range(len(ids)))
    assert rt.execution_ids(seq + 1) == ids


# 9 --------------------------------------------------------------------------
def test_report_verdict_math(mod):
    rt = mod.RedTeam()
    rt.plan("eng-r", 1)
    rep = rt.report("eng-r", 2)
    assert rep.n_steps == 0
    assert rep.verdict == "not-started"
    assert rep.phase_coverage == ()
    assert rep.integrity_ok is True
    assert rep.verify()

    rt.execute("eng-r", 3, phase="kickoff", outcome="completed")
    rep = rt.report("eng-r", 4)
    assert rep.n_steps == 1
    assert rep.verdict == "partial"
    assert rep.phase_coverage == ("kickoff",)

    rt.execute("eng-r", 5, phase="fieldwork", outcome="blocked")
    rep = rt.report("eng-r", 6)
    assert rep.n_steps == 2
    assert rep.verdict == "partial"
    assert rep.phase_coverage == ("kickoff",)
    assert dict(rep.outcome_tallies) == {
        "completed": 1,
        "blocked": 1,
        "deferred": 0,
        "not-attempted": 0,
    }

    rt.execute("eng-r", 7, phase="debrief", outcome="completed")
    rt.execute("eng-r", 8, phase="remediation-validation", outcome="completed")
    rt.execute("eng-r", 9, phase="fieldwork", outcome="completed")
    rep = rt.report("eng-r", 10)
    assert rep.n_steps == 5
    assert rep.verdict == "complete"
    assert rep.phase_coverage == mod.PHASES
    assert rep.verify()


# 10 -------------------------------------------------------------------------
def test_report_is_pure_read(mod):
    rt = mod.RedTeam()
    rt.plan("eng-p", 1)
    rt.execute("eng-p", 2, phase="kickoff", outcome="completed")
    rows_before = len(rt.audit_log(3))
    r1 = rt.report("eng-p", 4)
    r2 = rt.report("eng-p", 4)  # same seq twice: reads never consume
    assert r1 == r2
    assert len(rt.audit_log(5)) == rows_before
    with pytest.raises(mod.UnknownEngagementError):
        rt.report("no-such-eng", 6)


# 11 -------------------------------------------------------------------------
def test_seq_discipline(mod):
    rt = mod.RedTeam()
    with pytest.raises(mod.SeqOrderError):
        rt.plan("eng-s", 0)
    rt.plan("eng-s", 1)
    # Rewinds raise bare: no rejected row, seq untouched.
    rejected_before = sum(
        1 for row in rt.audit_log(2) if row["kind"] == "rejected"
    )
    with pytest.raises(mod.SeqOrderError):
        rt.plan("eng-s2", 1)
    with pytest.raises(mod.SeqOrderError):
        rt.execute("eng-s", 1)
    rejected_after = sum(
        1 for row in rt.audit_log(2) if row["kind"] == "rejected"
    )
    assert rejected_after == rejected_before
    # Malformed seqs raise bare.
    for bad in (True, "2", 2.0, None, -1):
        with pytest.raises(mod.SeqOrderError):
            rt.plan("eng-s3", bad)
    # Failed mutations consume their seq and keep order.
    with pytest.raises(mod.BadPhaseError):
        rt.execute("eng-s", 2, phase="nope")
    with pytest.raises(mod.SeqOrderError):
        rt.execute("eng-s", 2)  # already consumed
    ok = rt.execute("eng-s", 3, phase="fieldwork", outcome="completed")
    assert ok.execution_id == "exe-1"


# 12 -------------------------------------------------------------------------
def test_audit_shapes_leak_ban_and_bad_kind(mod):
    for kind in mod.AUDIT_KINDS:
        row = mod.red_team_audit_event(kind, 7, engagement_id="eng-a")
        assert row["schema"] == "audit.ndjson/1"
        assert row["kind"] == kind
        assert row["seq"] == 7
        assert row["details"]["engagement_id"] == "eng-a"
    banned = [
        "objective",
        "scope",
        "evidence",
        "findings",
        "transcript",
        "payload",
        "target",
        "details",
        "content",
        "data",
        "text",
    ]
    for key in banned:
        with pytest.raises(mod.AuditKindError):
            mod.red_team_audit_event("planned", 1, **{key: "x"})
    with pytest.raises(mod.AuditKindError):
        mod.red_team_audit_event("hacked", 1)
    with pytest.raises(mod.SeqOrderError):
        mod.red_team_audit_event("planned", -1)
    with pytest.raises(mod.SeqOrderError):
        mod.red_team_audit_event("planned", True)


# 13 -------------------------------------------------------------------------
def test_cross_instance_determinism_and_tamper_breaks_verify(mod):
    a, b = mod.RedTeam(), mod.RedTeam()
    ra = a.plan("eng-t", 1, engagement_type="continuous",
                scope_digest=_pin("s"))
    rb = b.plan("eng-t", 1, engagement_type="continuous",
                scope_digest=_pin("s"))
    assert ra.digest == rb.digest
    assert ra == rb
    ea = a.execute("eng-t", 2, phase="fieldwork", outcome="completed")
    eb = b.execute("eng-t", 2, phase="fieldwork", outcome="completed")
    assert ea.digest == eb.digest
    rep_a = a.report("eng-t", 3)
    rep_b = b.report("eng-t", 3)
    assert rep_a.digest == rep_b.digest
    # Tamper breaks verify(): reported as data, never raised.
    object.__setattr__(ea, "outcome", "tampered")
    assert ea.verify() is False
    rep = a.report("eng-t", 4)
    assert rep.integrity_ok is False
    assert rep.verify() is True


# 14 -------------------------------------------------------------------------
def test_views_stats_and_frozen_records(mod):
    rt = mod.RedTeam()
    rt.plan("eng-f1", 1, engagement_type="tabletop")
    rt.plan("eng-f2", 2, engagement_type="continuous")
    rt.execute("eng-f1", 3, phase="kickoff", outcome="completed")
    rt.execute("eng-f2", 4, phase="fieldwork", outcome="deferred")
    assert rt.engagement_ids(5) == ("eng-f1", "eng-f2")
    assert rt.stats(6) == {"engagements": 2, "executions": 2}
    for rec in (
        rt.engagement_record("eng-f1", 7),
        rt.execution_record("exe-1", 8),
        rt.report("eng-f1", 9),
    ):
        with pytest.raises(Exception):
            rec.seq = 999  # frozen dataclass: normal assignment raises
    with pytest.raises(mod.UnknownEngagementError):
        rt.engagement_record("nope", 10)
    with pytest.raises(mod.UnknownEngagementError):
        rt.executions_for("nope", 11)


# 15 -------------------------------------------------------------------------
def test_main_subprocess_and_concurrent_reads(mod):
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "red-team OK: plan, execute, report, pins, audit" in result.stdout
    rt = mod.RedTeam()
    rt.plan("eng-c", 1)
    rt.execute("eng-c", 2, phase="kickoff", outcome="completed")
    errors = []

    def reader():
        try:
            for _ in range(50):
                assert rt.report("eng-c", 3).n_steps == 1
                assert rt.stats(4)["executions"] == 1
                assert len(rt.audit_log(5)) == 2
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
