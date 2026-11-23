"""Tests for the GRC lifecycle decision ledger (15 tests)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "grc.py"


def load_module():
    """Import the module standalone via importlib (frozen dataclasses
    need the module registered in sys.modules first)."""
    import importlib.util

    sys.modules.pop("grc", None)
    spec = importlib.util.spec_from_file_location("grc", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["grc"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def g(mod):
    return mod.GRC()


def good_digest(label="grc"):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def test_version_and_schema_pins():
    mod = load_module()
    assert mod.VERSION == "grc.v1"
    assert mod.SCHEMA == "northstar.grc.v1"


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


def test_register_framework_roundtrip_verify_and_views(g, mod):
    rec = g.register_framework("fw-iso", "iso-27001", 1)
    assert rec.framework_id == "fw-iso"
    assert rec.framework == "iso-27001"
    assert rec.verify()
    assert g.framework_record("fw-iso", 2) is rec
    assert g.framework_ids(3) == ("fw-iso",)
    # duplicate refused fail-closed
    with pytest.raises(mod.DuplicateFrameworkError):
        g.register_framework("fw-iso", "soc-2", 4)
    assert g.stats(5)["rejected"] == 1


def test_register_framework_bad_inputs_and_vocabulary(g, mod):
    seq = 100
    for bad in (None, 1, True, b"x", "", "has space", "x" * 257):
        with pytest.raises(mod.BadIdError):
            g.register_framework(bad, "iso-27001", seq)
        seq += 1
    # framework vocabulary
    for i, bad_fw in enumerate(("iso9001", "", None, 1, True)):
        with pytest.raises(mod.BadFrameworkError):
            g.register_framework(f"fw-voc-{i}", bad_fw, seq)
        seq += 1
    # all six frameworks accepted
    for fw in ("iso-27001", "soc-2", "nist-csf", "hipaa", "gdpr", "pci-dss"):
        g.register_framework(f"fw-acc-{fw}", fw, seq)
        seq += 1
    assert g.stats(seq)["frameworks"] == 6


def test_assess_roundtrip_verify_and_views(g, mod):
    g.register_framework("fw1", "soc-2", 1)
    rec = g.assess("fw1", "cc7", 2, finding="non-compliant",
                   risk_level="high", evidence_digest=good_digest("e1"))
    assert rec.assessment_id == "asm-1"
    assert rec.framework_id == "fw1"
    assert rec.finding == "non-compliant"
    assert rec.risk_level == "high"
    assert rec.verify()
    assert g.assessment_record("asm-1", 3) is rec
    assert g.assessment_ids(4) == ("asm-1",)
    assert g.assessments_for("fw1", 5) == ("asm-1",)
    # unknown framework refused
    with pytest.raises(mod.UnknownFrameworkError):
        g.assess("nope", "s", 6)


def test_assess_bad_inputs_and_vocabulary(g, mod):
    g.register_framework("fw1", "hipaa", 1)
    seq = 2
    for bad in ("iso9001-finding", "", None, 1, True):
        with pytest.raises(mod.BadFindingError):
            g.assess("fw1", "s", seq, finding=bad)
        seq += 1
    for bad in ("super-high", "", None, 1, True):
        with pytest.raises(mod.BadRiskLevelError):
            g.assess("fw1", "s", seq, risk_level=bad)
        seq += 1
    # bad digest refused
    with pytest.raises(mod.BadDigestError):
        g.assess("fw1", "s", seq, evidence_digest="not-a-digest")
    seq += 1
    # all findings x all risk levels accepted
    for finding in ("compliant", "non-compliant", "partial",
                    "not-applicable"):
        for risk in ("low", "medium", "high", "critical"):
            g.assess("fw1", f"scope-{finding}-{risk}", seq, finding=finding,
                     risk_level=risk)
            seq += 1
    assert g.stats(seq)["assessments"] == 16


def test_remediate_roundtrip_verify_and_chain(g, mod):
    g2 = mod.GRC()
    g2.register_framework("fw1", "gdpr", 1)
    a = g2.assess("fw1", "dpa", 2, finding="partial", risk_level="medium")
    r1 = g2.remediate(a.assessment_id, 3, action="policy-update")
    assert r1.remediation_id == "rem-1"
    assert r1.assessment_id == a.assessment_id
    assert r1.verify()
    r2 = g2.remediate(a.assessment_id, 4, action="reassess")
    assert r2.remediation_id == "rem-2"
    assert g2.remediations_for(a.assessment_id, 5) == ("rem-1", "rem-2")
    assert g2.remediation_record("rem-1", 6) is r1


def test_remediate_refusals(g, mod):
    g.register_framework("fw1", "iso-27001", 1)
    a_clean = g.assess("fw1", "s1", 2, finding="compliant")
    a_na = g.assess("fw1", "s2", 3, finding="not-applicable")
    a_open = g.assess("fw1", "s3", 4, finding="non-compliant")
    # compliant / not-applicable findings need no remediation
    with pytest.raises(mod.RemediationNotNeededError):
        g.remediate(a_clean.assessment_id, 5)
    with pytest.raises(mod.RemediationNotNeededError):
        g.remediate(a_na.assessment_id, 6)
    # unknown assessment refused
    with pytest.raises(mod.UnknownAssessmentError):
        g.remediate("asm-999", 7)
    # bad action refused
    with pytest.raises(mod.BadRemediationError):
        g.remediate(a_open.assessment_id, 8, action="fix-it")
    # all pinned actions accepted
    for i, action in enumerate(
            ("patch", "reconfigure", "training", "policy-update",
             "reassess", "accept-risk", "vendor-fix")):
        g.remediate(a_open.assessment_id, 10 + i, action=action)
    assert g.stats(20)["remediations"] == 7


def test_certify_certified_as_data(g, mod):
    g.register_framework("fw1", "nist-csf", 1)
    a1 = g.assess("fw1", "govern", 2, finding="non-compliant",
                  risk_level="high")
    a2 = g.assess("fw1", "identify", 3, finding="partial",
                  risk_level="medium")
    # not certified while findings are open
    before = g.certify("fw1", 4)
    assert before.verify()
    assert before.certified is False
    assert before.n_assessments == 2
    # remediate every open finding
    g.remediate(a1.assessment_id, 5, action="patch")
    g.remediate(a2.assessment_id, 6, action="accept-risk")
    after = g.certify("fw1", 7)
    assert after.verify()
    assert after.certified is True
    assert after.remediated_assessments == ("asm-1", "asm-2")
    # tamper breaks verify
    object.__setattr__(after, "certified", False)
    assert after.verify() is False


def test_certify_edge_cases_and_read_purity(g, mod):
    g.register_framework("fw1", "pci-dss", 1)
    # zero assessments -> certified False, not raised
    empty = g.certify("fw1", 2)
    assert empty.certified is False
    assert empty.n_assessments == 0
    # pure read: same seq reused, no audit rows, no seq consumed
    g.certify("fw1", 2)
    assert len(g.audit_log(3)) == 1  # only the framework-registered row
    assert g.stats(4)["rejected"] == 0
    # unknown framework refused
    with pytest.raises(mod.UnknownFrameworkError):
        g.certify("nope", 5)


def test_seq_discipline_rewind_bare_and_malformed(g, mod):
    g.register_framework("fw1", "soc-2", 1)
    # rewind raises bare, consumes nothing, no rejected row
    with pytest.raises(mod.SeqOrderError):
        g.assess("fw1", "s", 1)
    assert g.stats(2)["rejected"] == 0
    # malformed seqs
    for bad in (None, "2", 2.0, True, -1):
        with pytest.raises(mod.SeqOrderError):
            g.assess("fw1", "s", bad)
    # failed mutation consumes seq + books rejected row
    with pytest.raises(mod.UnknownFrameworkError):
        g.assess("no-fw", "s", 2)
    assert g.stats(3)["rejected"] == 1
    rows = g.audit_log(4)
    assert rows[-1]["kind"] == "grc.rejected"


def test_audit_shapes_leak_ban_and_bad_kind(g, mod):
    g.register_framework("fw1", "iso-27001", 1)
    a = g.assess("fw1", "s1", 2, finding="non-compliant")
    g.remediate(a.assessment_id, 3, action="patch")
    rows = g.audit_log(4)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["grc.framework-registered", "grc.assessed",
                     "grc.remediated"]
    for row in rows:
        assert row["audit_version"] == "audit.ndjson/1"
        assert row["schema"] == "northstar.grc.v1"
    # raw content banned at the audit boundary (builder-level)
    for bad_key in ("evidence", "plan", "notes", "content", "summary"):
        with pytest.raises(mod.AuditKindError):
            mod.grc_audit_event("assessed", {bad_key: "x"}, 5)
    # bad kind refused
    with pytest.raises(mod.AuditKindError):
        mod.grc_audit_event("bogus", {}, 5)


def test_cross_instance_digest_determinism_and_views(g, mod):
    g1, g2 = mod.GRC(), mod.GRC()
    for ginst in (g1, g2):
        ginst.register_framework("fw1", "hipaa", 1)
        ginst.assess("fw1", "phi", 2, finding="partial",
                     risk_level="critical")
    r1 = g1.certify("fw1", 3)
    r2 = g2.certify("fw1", 3)
    assert r1.digest == r2.digest
    assert r1.as_dict()["digest"] == r1.digest
    assert g1.framework_ids(4) == ("fw1",)
    assert g1.assessment_ids(5) == ("asm-1",)


def test_frozen_records_and_concurrency_smoke(g, mod):
    g.register_framework("fw1", "gdpr", 1)
    rec = g.assess("fw1", "s1", 2, finding="compliant")
    with pytest.raises(Exception):
        rec.finding = "non-compliant"  # frozen dataclass
    errors = []

    def reader():
        try:
            for i in range(50):
                g.certify("fw1", 10)
                g.stats(11)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_main_subprocess_check():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "grc OK: register, assess, remediate, certify, pins, audit" \
        in result.stdout
