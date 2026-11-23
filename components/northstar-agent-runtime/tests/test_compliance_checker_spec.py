"""test_compliance_checker_spec.py — spec API (audit/attest/remediate) tests.

Additive companion to test_compliance_checker.py: covers only the spec
extension (audit engagements, attestations, remediations) plus integration
with the pre-existing control layer. The pre-existing suite is run as-is
in test 14 to prove zero behavior change.
"""

import ast
import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

COMP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMP_DIR))

from compliance_checker import (  # noqa: E402
    VERSION,
    SCHEMA,
    AUDIT_KINDS,
    ATTEST_VERDICTS,
    REMEDIATION_ACTIONS,
    ComplianceChecker,
    ComplianceError,
    UnknownControlError,
    UnknownAuditError,
    DuplicateAuditError,
    DuplicateAttestationError,
    UncheckedScopeError,
    BadVerdictError,
    BadActionError,
    AuditRecord,
    AttestationRecord,
    RemediationRecord,
    compliance_checker_audit_event,
    main,
)


def _checker_with_passing_control():
    cc = ComplianceChecker()
    cc.define_control("CC6.1", "SOC2", "logical access security",
                      ("access-review", "policy-doc"), 0)
    cc.attach_evidence("CC6.1", "access-review",
                       {"reviewer": "sec-team", "quarter": "Q3"}, 1)
    cc.attach_evidence("CC6.1", "policy-doc", {"version": "3"}, 2)
    result = cc.check("CC6.1", 3)
    assert result.verdict == "pass"
    return cc


def test_01_audit_roundtrip():
    cc = _checker_with_passing_control()
    cc.define_control("CC7.2", "SOC2", "monitoring",
                      ("monitoring-log",), 4)
    rec = cc.audit("audit-2026", ("CC7.2", "CC6.1"), 5)
    assert isinstance(rec, AuditRecord)
    assert rec.audit_id == "audit-2026"
    assert rec.scope == ("CC6.1", "CC7.2")  # sorted for a deterministic pin
    assert rec.scope_digest.startswith("sha256:")
    assert rec.digest.startswith("sha256:")
    assert rec.version == VERSION
    assert rec.seq == 5
    d = rec.as_dict()
    assert d["audit_id"] == "audit-2026"
    assert d["scope"] == ["CC6.1", "CC7.2"]
    assert cc.audit_record("audit-2026") == rec
    assert cc.audit_ids() == ("audit-2026",)


def test_02_audit_bad_inputs():
    cc = _checker_with_passing_control()
    with pytest.raises(ComplianceError):
        cc.audit("", ("CC6.1",), 4)
    with pytest.raises(ComplianceError):
        cc.audit("a", (), 4)
    with pytest.raises(ComplianceError):
        cc.audit("a", ("CC6.1", "CC6.1"), 4)
    with pytest.raises(UnknownControlError):
        cc.audit("a", ("NOPE",), 4)
    cc.audit("a", ("CC6.1",), 4)
    with pytest.raises(DuplicateAuditError):
        cc.audit("a", ("CC6.1",), 5)
    with pytest.raises(UnknownAuditError):
        cc.audit_record("missing")


def test_03_attest_roundtrip():
    cc = _checker_with_passing_control()
    cc.audit("audit-2026", ("CC6.1",), 4)
    rec = cc.attest("audit-2026", "compliant", 5, auditor="ext-auditor")
    assert isinstance(rec, AttestationRecord)
    assert rec.attestation_id == "attest-1"
    assert rec.audit_id == "audit-2026"
    assert rec.verdict == "compliant"
    assert rec.auditor == "ext-auditor"
    assert rec.statement_digest.startswith("sha256:")
    assert rec.digest.startswith("sha256:")
    assert rec.version == VERSION
    d = rec.as_dict()
    assert d["attestation_id"] == "attest-1"
    assert d["verdict"] == "compliant"
    assert cc.attestation_record("audit-2026") == rec


def test_04_attest_verdict_vocabulary():
    for i, verdict in enumerate(ATTEST_VERDICTS):
        cc = _checker_with_passing_control()
        cc.audit("a", ("CC6.1",), 4)
        rec = cc.attest("a", verdict, 5)
        assert rec.verdict == verdict
        assert rec.attestation_id == "attest-1"


def test_05_attest_refusals():
    cc = _checker_with_passing_control()
    cc.audit("a", ("CC6.1",), 4)
    with pytest.raises(UnknownAuditError):
        cc.attest("missing", "compliant", 5)
    with pytest.raises(BadVerdictError):
        cc.attest("a", "totally-fine", 5)
    with pytest.raises(BadVerdictError):
        cc.attest("a", "", 5)
    cc.attest("a", "qualified", 5)
    with pytest.raises(DuplicateAttestationError):
        cc.attest("a", "compliant", 6)
    with pytest.raises(ComplianceError):
        cc.attest("a", "compliant", True)
    with pytest.raises(UnknownAuditError):
        cc.attestation_record("missing")


def test_06_attest_unchecked_scope():
    cc = ComplianceChecker()
    cc.define_control("CC6.1", "SOC2", "logical access security",
                      ("access-review",), 0)
    cc.audit("a", ("CC6.1",), 1)
    with pytest.raises(UncheckedScopeError):
        cc.attest("a", "compliant", 2)
    # After booking the check, the same seq is still valid and attests fine
    # (this module validates before claiming: refusals do not burn seq).
    cc.check("CC6.1", 2)
    rec = cc.attest("a", "compliant", 3)
    assert rec.verdict == "compliant"


def test_07_remediate_roundtrip():
    cc = _checker_with_passing_control()
    rec = cc.remediate("CC6.1", "recheck", 4)
    assert isinstance(rec, RemediationRecord)
    assert rec.remediation_id == "rem-1"
    assert rec.control_id == "CC6.1"
    assert rec.action == "recheck"
    assert rec.plan_digest == ""
    assert rec.digest.startswith("sha256:")
    assert rec.version == VERSION
    d = rec.as_dict()
    assert d["remediation_id"] == "rem-1"
    assert d["action"] == "recheck"
    assert cc.remediation_record("rem-1") == rec
    # Escalation chain allowed: a second remediation is another record.
    rec2 = cc.remediate("CC6.1", "fix-evidence", 5,
                        plan_digest="sha256:" + "ab" * 32)
    assert rec2.remediation_id == "rem-2"


def test_08_remediate_action_vocabulary():
    for i, action in enumerate(REMEDIATION_ACTIONS):
        cc = _checker_with_passing_control()
        rec = cc.remediate("CC6.1", action, 4)
        assert rec.action == action
        assert rec.remediation_id == "rem-1"


def test_09_remediate_refusals():
    cc = _checker_with_passing_control()
    with pytest.raises(UnknownControlError):
        cc.remediate("NOPE", "recheck", 4)
    with pytest.raises(BadActionError):
        cc.remediate("CC6.1", "pray", 4)
    with pytest.raises(BadActionError):
        cc.remediate("CC6.1", "", 4)
    with pytest.raises(ComplianceError):
        cc.remediate("CC6.1", "recheck", 4, plan_digest="not-a-pin")
    with pytest.raises(ComplianceError):
        cc.remediation_record("rem-99")


def test_10_seq_discipline():
    cc = _checker_with_passing_control()
    cc.audit("a", ("CC6.1",), 4)
    with pytest.raises(ComplianceError):
        cc.audit("b", ("CC6.1",), 4)  # rewind
    with pytest.raises(ComplianceError):
        cc.audit("b", ("CC6.1",), True)  # bool
    with pytest.raises(ComplianceError):
        cc.audit("b", ("CC6.1",), -1)  # negative
    with pytest.raises(ComplianceError):
        cc.audit("b", ("CC6.1",), "5")  # non-int
    rec = cc.audit("b", ("CC6.1",), 5)
    assert rec.seq == 5


def test_11_audit_builder_kinds():
    for kind in ("audit-opened", "attested", "remediated"):
        assert kind in AUDIT_KINDS
        ev = compliance_checker_audit_event(kind, 1, control_id="CC6.1")
        assert ev["schema"] == SCHEMA
        assert ev["kind"] == kind
    with pytest.raises(ComplianceError):
        compliance_checker_audit_event("nonsense-kind", 1)


def test_12_records_frozen():
    cc = _checker_with_passing_control()
    aud = cc.audit("a", ("CC6.1",), 4)
    att = cc.attest("a", "compliant", 5)
    rem = cc.remediate("CC6.1", "recheck", 6)
    for rec, field_name in ((aud, "audit_id"), (att, "verdict"),
                            (rem, "action")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(rec, field_name, "mutated")


def test_13_cross_instance_determinism():
    def build():
        cc = _checker_with_passing_control()
        aud = cc.audit("a", ("CC6.1",), 4)
        att = cc.attest("a", "compliant", 5, auditor="x")
        rem = cc.remediate("CC6.1", "recheck", 6)
        return aud.digest, att.digest, rem.digest

    first, second = build(), build()
    assert first == second


def test_14_preexisting_suite_green():
    proc = subprocess.run(
        [sys.executable, "-m", "pytest",
         str(COMP_DIR / "tests" / "test_compliance_checker.py"), "-q"],
        capture_output=True, text=True, cwd=str(COMP_DIR), timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "failed" not in proc.stdout


def test_15_main_and_stdlib():
    proc = subprocess.run(
        [sys.executable, str(COMP_DIR / "compliance_checker.py")],
        capture_output=True, text=True, cwd=str(COMP_DIR), timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "compliance-checker spec OK: audit, attest, remediate" in proc.stdout
    tree = ast.parse((COMP_DIR / "compliance_checker.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])
    allowed = {"__future__", "hashlib", "json", "math", "threading",
               "dataclasses", "typing"}
    assert imported <= allowed, imported - allowed
