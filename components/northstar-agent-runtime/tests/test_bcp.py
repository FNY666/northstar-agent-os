"""Tests for the BCP governance ledger (15 tests)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "bcp.py"


def load_module():
    """Import the module standalone via importlib (frozen dataclasses
    need the module registered in sys.modules first)."""
    import importlib.util

    sys.modules.pop("bcp", None)
    spec = importlib.util.spec_from_file_location("bcp", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["bcp"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def bcp(mod):
    return mod.BCP()


def good_digest(label="x"):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def test_version_and_schema_pins():
    mod = load_module()
    assert mod.VERSION == "bcp.v1"
    assert mod.SCHEMA == "northstar.bcp.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib", "re", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


def test_plan_roundtrip_verify_and_views(bcp, mod):
    rec = bcp.plan("plan-tech", "technology", 1, criticality="high",
                   objective_digest=good_digest("obj"))
    assert rec.plan_id == "plan-tech"
    assert rec.scope == "technology"
    assert rec.criticality == "high"
    assert rec.verify()
    assert bcp.plan_record("plan-tech", 2) is rec
    assert bcp.plan_ids(3) == ("plan-tech",)
    assert bcp.is_active("plan-tech", 4) is False
    # duplicate refused fail-closed
    with pytest.raises(mod.DuplicatePlanError):
        bcp.plan("plan-tech", "people", 5)
    assert bcp.stats(6)["rejected"] == 1


def test_plan_bad_inputs_and_vocabulary(bcp, mod):
    seq = 10
    for bad in (None, 1, True, b"x", "", "has space", "x" * 257):
        with pytest.raises(mod.BadIdError):
            bcp.plan(bad, "technology", seq)
        seq += 1
    with pytest.raises(mod.BadScopeError):
        bcp.plan("p-badscope", "datacenter", seq)
    seq += 1
    with pytest.raises(mod.BadCriticalityError):
        bcp.plan("p-badcrit", "technology", seq, criticality="extreme")
    seq += 1
    with pytest.raises(mod.BadDigestError):
        bcp.plan("p-baddigest", "technology", seq,
                 objective_digest="not-a-digest")
    seq += 1
    # raw objective text is refused: only digest pins cross the boundary
    with pytest.raises(mod.BadDigestError):
        bcp.plan("p-raw", "technology", seq,
                 objective_digest="restore everything ASAP")
    # seq burned on each failed mutation -> rejected rows booked
    assert bcp.stats(seq + 1)["rejected"] == 11


def test_test_lifecycle_and_outcome_vocabulary(bcp, mod):
    bcp.plan("p1", "facilities", 1)
    kinds = ["walkthrough", "simulation", "parallel", "full-interruption",
             "checklist"]
    outcomes = ["pass", "fail", "inconclusive"]
    seq = 2
    for i, kind in enumerate(kinds):
        for j, outcome in enumerate(outcomes):
            tid = f"t-{i}-{j}"
            rec = bcp.test("p1", tid, seq, kind=kind, outcome=outcome,
                           findings_digest=good_digest(tid))
            assert rec.verify()
            seq += 1
    assert bcp.tests_for("p1", seq) == tuple(
        f"t-{i}-{j}" for i in range(5) for j in range(3))
    rep = bcp.status("p1", seq + 1)
    assert rep.verify()
    assert rep.tests == 15 and rep.passed == 5 and rep.failed == 5
    assert rep.inconclusive == 5 and rep.state == "ready"
    # duplicate test id refused
    with pytest.raises(mod.DuplicateTestError):
        bcp.test("p1", "t-0-0", seq + 2)
    assert bcp.stats(seq + 3)["rejected"] == 1


def test_test_bad_inputs(bcp, mod):
    bcp.plan("p1", "people", 1)
    with pytest.raises(mod.UnknownPlanError):
        bcp.test("nope", "t-1", 2)
    with pytest.raises(mod.BadKindError):
        bcp.test("p1", "t-1", 3, kind="game-day")
    with pytest.raises(mod.BadOutcomeError):
        bcp.test("p1", "t-1", 4, outcome="passed")
    with pytest.raises(mod.BadDigestError):
        bcp.test("p1", "t-1", 5, findings_digest="raw findings text")
    # raw findings refused: digest pin only
    with pytest.raises(mod.BadDigestError):
        bcp.test("p1", "t-1", 6,
                 findings_digest="the CEO laptop was unpatched")
    assert bcp.stats(7)["rejected"] == 5


def test_activate_requires_passing_test(bcp, mod):
    bcp.plan("p1", "process", 1)
    bcp.test("p1", "t-fail", 2, kind="walkthrough", outcome="fail")
    # untested-passing plan refuses activation fail-closed
    with pytest.raises(mod.NoPassingTestError):
        bcp.activate("p1", 3)
    # inconclusive-only also refuses
    bcp.test("p1", "t-inc", 4, kind="checklist", outcome="inconclusive")
    with pytest.raises(mod.NoPassingTestError):
        bcp.activate("p1", 5)
    # unknown plan refused
    with pytest.raises(mod.UnknownPlanError):
        bcp.activate("ghost", 6)
    assert bcp.stats(7)["rejected"] == 3


def test_activate_lifecycle_and_reactivation(bcp, mod):
    bcp.plan("p1", "supply-chain", 1)
    bcp.test("p1", "t-1", 2, kind="simulation", outcome="pass")
    act = bcp.activate("p1", 3, scenario_digest=good_digest("disruption"))
    assert act.act_id == "act-1"
    assert act.verify()
    assert bcp.is_active("p1", 4) is True
    rep = bcp.status("p1", 5)
    assert rep.state == "active" and rep.active_act_id == "act-1"
    # second activation while active refused fail-closed
    with pytest.raises(mod.AlreadyActiveError):
        bcp.activate("p1", 6)
    dct = bcp.deactivate("p1", 7, reason="disruption-resolved")
    assert dct.dct_id == "dct-1"
    assert dct.verify()
    assert bcp.is_active("p1", 8) is False
    # reactivation allowed after deactivation (history kept)
    act2 = bcp.activate("p1", 9)
    assert act2.act_id == "act-2"
    assert bcp.activations_for("p1", 10) == ("act-1", "act-2")
    assert bcp.stats(11)["rejected"] == 1


def test_deactivate_refusals(bcp, mod):
    bcp.plan("p1", "communications", 1)
    bcp.test("p1", "t-1", 2, outcome="pass")
    # deactivate with nothing active refused
    with pytest.raises(mod.NotActiveError):
        bcp.deactivate("p1", 3)
    bcp.activate("p1", 4)
    with pytest.raises(mod.BadReasonError):
        bcp.deactivate("p1", 5, reason="we-felt-like-it")
    with pytest.raises(mod.UnknownPlanError):
        bcp.deactivate("ghost", 6)
    assert bcp.stats(7)["rejected"] == 3


def test_seq_discipline(bcp, mod):
    bcp.plan("p1", "technology", 1)
    # rewind raises bare: no rejected row, seq not consumed
    n_rows = len(bcp.audit_log(2))
    with pytest.raises(mod.SeqOrderError):
        bcp.plan("p2", "technology", 1)
    assert len(bcp.audit_log(2)) == n_rows
    assert bcp.stats(2)["rejected"] == 0
    # malformed seqs refused
    for bad in (True, "3", 1.5, -1, None):
        with pytest.raises(mod.SeqOrderError):
            bcp.plan("p-bad", "technology", bad)
    # failed mutation consumes its seq: next use of the same seq rewinds
    with pytest.raises(mod.DuplicatePlanError):
        bcp.plan("p1", "people", 3)
    with pytest.raises(mod.SeqOrderError):
        bcp.test("p1", "t-1", 3, kind="walkthrough")
    assert bcp.stats(4)["rejected"] == 1
    # views never consume seq and write no audit rows
    rows = len(bcp.audit_log(4))
    bcp.status("p1", 4)
    bcp.plan_ids(4)
    bcp.stats(4)
    assert len(bcp.audit_log(4)) == rows


def test_audit_shapes_leak_ban_and_bad_kind(bcp, mod):
    bcp.plan("p1", "people", 1)
    bcp.test("p1", "t-1", 2, outcome="pass")
    bcp.activate("p1", 3)
    bcp.deactivate("p1", 4)
    rows = bcp.audit_log(5)
    assert [r["kind"] for r in rows] == [
        "bcp.planned", "bcp.tested", "bcp.activated", "bcp.deactivated"]
    for r in rows:
        assert r["audit_version"] == "audit.ndjson/1"
        assert r["schema"] == "northstar.bcp.v1"
    # banned raw-text keys refused at the audit boundary
    with pytest.raises(mod.AuditKindError):
        mod.bcp_audit_event("tested", {"findings": "raw text"}, 6)
    with pytest.raises(mod.AuditKindError):
        mod.bcp_audit_event("activated", {"scenario": "datacenter fire"}, 6)
    # unknown kind refused
    with pytest.raises(mod.AuditKindError):
        mod.bcp_audit_event("launched", {}, 6)


def test_cross_instance_digest_determinism_and_tamper(bcp, mod):
    other = mod.BCP()
    bcp.plan("p1", "technology", 1, criticality="high",
             objective_digest=good_digest("obj"))
    other.plan("p1", "technology", 1, criticality="high",
               objective_digest=good_digest("obj"))
    assert bcp.plan_record("p1", 2).digest == other.plan_record("p1", 2).digest
    # tamper breaks verify() as data
    rec = bcp.plan_record("p1", 3)
    object.__setattr__(rec, "criticality", "low")
    assert rec.verify() is False


def test_status_unknown_plan_and_view_purity(bcp, mod):
    bcp.plan("p1", "facilities", 1)
    with pytest.raises(mod.UnknownPlanError):
        bcp.status("ghost", 2)
    with pytest.raises(mod.UnknownPlanError):
        bcp.tests_for("ghost", 2)
    with pytest.raises(mod.UnknownPlanError):
        bcp.plan_record("ghost", 2)
    rows = len(bcp.audit_log(3))
    rep = bcp.status("p1", 3)
    assert rep.integrity_ok is True
    assert rep.state == "ready" and rep.tests == 0
    # pure read: same seq reused, no audit rows, nothing consumed
    bcp.status("p1", 3)
    bcp.stats(3)
    assert len(bcp.audit_log(3)) == rows
    assert bcp.stats(3)["seq"] == 1


def test_frozen_and_concurrency_smoke(bcp, mod):
    bcp.plan("p1", "technology", 1, criticality="high")
    rec = bcp.plan_record("p1", 2)
    with pytest.raises(Exception):
        rec.criticality = "low"  # frozen dataclass
    assert rec.criticality == "high"
    bcp.test("p1", "t-1", 3, outcome="pass")
    errors = []

    def reader():
        try:
            for _ in range(200):
                bcp.status("p1", 4)
                bcp.plan_ids(4)
                bcp.stats(4)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "bcp OK: plan, test, activate, deactivate, pins, audit")
