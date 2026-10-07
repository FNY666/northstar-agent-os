"""Tests for regulatory.py — simulated registration/reporting ledger."""

import ast
import importlib.util
import pathlib
import subprocess
import sys

import pytest

MODULE_PATH = pathlib.Path(__file__).resolve().parent.parent / "regulatory.py"


def _load():
    spec = importlib.util.spec_from_file_location("regulatory", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["regulatory"] = module
    spec.loader.exec_module(module)
    return module


reg_mod = _load()


def test_version_and_schema_pins():
    assert reg_mod.VERSION == "regulatory.v1"
    assert reg_mod.SCHEMA == "northstar.regulatory.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_register_roundtrip():
    reg = reg_mod.Regulatory()
    record = reg.register("sys-1", "EU-AI-Act", 1)
    assert record.system_id == "sys-1"
    assert record.framework == "EU-AI-Act"
    assert record.digest.startswith("sha256:")
    assert len(record.digest) == len("sha256:") + 64
    assert record.as_dict()["schema"] == reg_mod.SCHEMA
    assert reg.stats()["systems"] == 1
    assert reg.registration("sys-1") is record
    assert reg.system_ids() == ("sys-1",)


def test_register_duplicate_and_bad_inputs():
    reg = reg_mod.Regulatory()
    reg.register("sys-1", "EU-AI-Act", 1)
    with pytest.raises(reg_mod.DuplicateSystemError):
        reg.register("sys-1", "EU-AI-Act", 2)
    bad_ids = ["", 123, None, ["x"], "x" * 129]
    for i, bad in enumerate(bad_ids, start=3):
        with pytest.raises(reg_mod.BadSystemError):
            reg.register(bad, "EU-AI-Act", i)
    with pytest.raises(reg_mod.BadFrameworkError):
        reg.register("sys-2", "Mars-Accords", 20)
    # all failures consumed their seq and booked rejected rows
    rejected = [r for r in reg.audit_log() if r["kind"] == "regulatory.rejected"]
    assert len(rejected) == 1 + len(bad_ids) + 1


def test_seq_discipline():
    reg = reg_mod.Regulatory()
    with pytest.raises(reg_mod.SeqOrderError):
        reg.register("sys-1", "EU-AI-Act", 0)
    with pytest.raises(reg_mod.SeqOrderError):
        reg.register("sys-1", "EU-AI-Act", True)
    with pytest.raises(reg_mod.SeqOrderError):
        reg.register("sys-1", "EU-AI-Act", "1")
    reg.register("sys-1", "EU-AI-Act", 1)
    with pytest.raises(reg_mod.SeqOrderError):
        reg.register("sys-2", "EU-AI-Act", 1)  # rewind
    with pytest.raises(reg_mod.UnknownSystemError):
        reg.registration("nope")


def test_report_roundtrip_and_ids():
    reg = reg_mod.Regulatory()
    reg.register("sys-1", "EU-AI-Act", 1)
    r1 = reg.report("sys-1", "conformity-assessment", 2)
    r2 = reg.report("sys-1", "annual-report", 3, outcome="accepted")
    assert r1.report_id == "rep-1"
    assert r2.report_id == "rep-2"
    assert r1.outcome == "submitted"
    assert r2.outcome == "accepted"
    assert r1.digest.startswith("sha256:")
    assert reg.report_record("rep-1") is r1
    assert reg.stats()["reports"] == 2


def test_report_bad_inputs():
    reg = reg_mod.Regulatory()
    reg.register("sys-1", "EU-AI-Act", 1)
    with pytest.raises(reg_mod.UnknownSystemError):
        reg.report("ghost", "conformity-assessment", 2)
    with pytest.raises(reg_mod.BadReportError):
        reg.report("sys-1", "birthday-card", 3)
    with pytest.raises(reg_mod.BadOutcomeError):
        reg.report("sys-1", "conformity-assessment", 4, outcome="filed-away")
    with pytest.raises(reg_mod.BadReportError):
        reg.report_record("rep-999")
    rejected = [r for r in reg.audit_log() if r["kind"] == "regulatory.rejected"]
    assert len(rejected) == 3


def test_comply_view():
    reg = reg_mod.Regulatory()
    reg.register("sys-1", "EU-AI-Act", 1)
    view = reg.comply("sys-1", 2)
    assert view.reports_submitted == 0
    assert view.compliant is False
    reg.report("sys-1", "conformity-assessment", 3)
    view = reg.comply("sys-1", 4)
    assert view.reports_submitted == 1
    assert view.reports_accepted == 1
    assert view.compliant is True
    assert view.framework == "EU-AI-Act"
    assert view.digest.startswith("sha256:")
    assert view.as_dict()["schema"] == reg_mod.SCHEMA
    reg.report("sys-1", "incident-notification", 5, outcome="rejected")
    view = reg.comply("sys-1", 6)
    assert view.reports_submitted == 2
    assert view.compliant is False
    with pytest.raises(reg_mod.UnknownSystemError):
        reg.comply("ghost", 7)


def test_audit_shapes_and_leak_ban():
    reg = reg_mod.Regulatory()
    reg.register("sys-1", "EU-AI-Act", 1)
    reg.report("sys-1", "conformity-assessment", 2)
    reg.comply("sys-1", 3)
    rows = reg.audit_log()
    kinds = [r["kind"] for r in rows]
    assert kinds == [
        "regulatory.registered",
        "regulatory.reported",
        "regulatory.compliance-checked",
    ]
    banned = {"payload", "text", "raw", "data", "value"}
    for row in rows:
        assert not (banned & set(row))
    with pytest.raises(reg_mod.AuditKindError):
        reg_mod.regulatory_audit_event("nope", 1)
    with pytest.raises(reg_mod.AuditKindError):
        reg_mod.regulatory_audit_event("registered", 1, payload="x")
    with pytest.raises(reg_mod.SeqOrderError):
        reg_mod.regulatory_audit_event("registered", -1)


def test_framework_vocabulary():
    reg = reg_mod.Regulatory()
    frameworks = [
        "EU-AI-Act",
        "US-EO-14110",
        "UK-Pro-Innovation",
        "China-GenAI-Measures",
        "Canada-AIDA",
        "Custom",
    ]
    for i, fw in enumerate(frameworks, start=1):
        record = reg.register(f"sys-{i}", fw, i)
        assert record.framework == fw
    assert reg.stats()["systems"] == len(frameworks)


def test_report_kind_vocabulary():
    reg = reg_mod.Regulatory()
    reg.register("sys-1", "EU-AI-Act", 1)
    kinds = [
        "conformity-assessment",
        "incident-notification",
        "annual-report",
        "risk-assessment",
        "audit-finding",
        "registration-update",
    ]
    for i, kind in enumerate(kinds, start=2):
        record = reg.report("sys-1", kind, i)
        assert record.kind == kind
    assert reg.stats()["reports"] == len(kinds)


def test_outcome_vocabulary():
    reg = reg_mod.Regulatory()
    reg.register("sys-1", "EU-AI-Act", 1)
    outcomes = ["submitted", "accepted", "rejected", "pending-review", "withdrawn"]
    for i, outcome in enumerate(outcomes, start=2):
        record = reg.report("sys-1", "conformity-assessment", i, outcome=outcome)
        assert record.outcome == outcome


def test_digest_determinism_and_tamper():
    reg = reg_mod.Regulatory()
    r1 = reg.register("sys-1", "EU-AI-Act", 1)
    reg2 = reg_mod.Regulatory()
    r2 = reg2.register("sys-1", "EU-AI-Act", 1)
    assert r1.digest == r2.digest
    reg3 = reg_mod.Regulatory()
    r3 = reg3.register("sys-1", "US-EO-14110", 1)
    assert r1.digest != r3.digest


def test_records_are_frozen():
    reg = reg_mod.Regulatory()
    record = reg.register("sys-1", "EU-AI-Act", 1)
    with pytest.raises(Exception):
        record.framework = "Custom"  # frozen dataclass
    report = reg.report("sys-1", "conformity-assessment", 2)
    with pytest.raises(Exception):
        report.outcome = "accepted"  # frozen dataclass


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "regulatory OK" in proc.stdout
