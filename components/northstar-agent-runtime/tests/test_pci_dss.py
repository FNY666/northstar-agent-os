"""Tests for the PCI DSS lifecycle decision ledger (15 tests)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "pci_dss.py"


def load_module():
    """Import the module standalone via importlib (frozen dataclasses
    need the module registered in sys.modules first)."""
    import importlib.util

    sys.modules.pop("pci_dss", None)
    spec = importlib.util.spec_from_file_location("pci_dss", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["pci_dss"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def p(mod):
    return mod.PCIDSS()


def good_digest(label="pci-dss"):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def test_version_and_schema_pins():
    mod = load_module()
    assert mod.VERSION == "pci-dss.v1"
    assert mod.SCHEMA == "northstar.pci-dss.v1"


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


def test_register_merchant_roundtrip_verify_and_views(p, mod):
    rec = p.register_merchant("merchant-1", "level-1", 1,
                              profile_digest=good_digest("profile"))
    assert rec.merchant_id == "merchant-1"
    assert rec.level == "level-1"
    assert rec.verify()
    assert p.merchant_record("merchant-1", 2) is rec
    assert p.merchant_ids(3) == ("merchant-1",)
    # duplicate refused fail-closed
    with pytest.raises(mod.DuplicateMerchantError):
        p.register_merchant("merchant-1", "level-2", 4)
    assert p.stats(5)["rejected"] == 1


def test_register_merchant_bad_inputs_and_vocabulary(p, mod):
    seq = 100
    for bad in (None, 1, True, b"x", "", "has space", "x" * 257):
        with pytest.raises(mod.BadIdError):
            p.register_merchant(bad, "level-1", seq)
        seq += 1
    for bad_level in (None, 1, True, "level-0", "level-5", "L1", ""):
        with pytest.raises(mod.BadLevelError):
            p.register_merchant("m", bad_level, seq)
        seq += 1
    for bad_digest in (1, True, "nope", "sha256:" + "g" * 64, b"x"):
        with pytest.raises(mod.BadDigestError):
            p.register_merchant("m", "level-1", seq, profile_digest=bad_digest)
        seq += 1
    for level in ("level-1", "level-2", "level-3", "level-4"):
        p.register_merchant(f"m-{level}", level, seq)
        seq += 1
    assert p.stats(seq)["merchants"] == 4
    assert p.stats(seq)["rejected"] == 19


def test_assess_roundtrip_minted_ids_and_verify(p, mod):
    p.register_merchant("merchant-1", "level-1", 1)
    a1 = p.assess("merchant-1", 2, requirement="req-04",
                  finding="non-compliant", severity="critical",
                  evidence_digest=good_digest("ev1"))
    assert a1.assessment_id == "asm-1"
    assert a1.verify()
    a2 = p.assess("merchant-1", 3, requirement="req-08")
    assert a2.assessment_id == "asm-2"
    assert a2.finding == "compliant"
    assert p.assessment_record("asm-1", 4) is a1
    assert p.assessment_ids(5) == ("asm-1", "asm-2")
    assert p.assessments_for("merchant-1", 6) == ("asm-1", "asm-2")
    with pytest.raises(mod.UnknownAssessmentError):
        p.assessment_record("asm-999", 7)


def test_assess_bad_inputs_and_seq_burn(p, mod):
    p.register_merchant("merchant-1", "level-1", 1)
    seq = 2
    with pytest.raises(mod.UnknownMerchantError):
        p.assess("ghost", seq)
    seq += 1
    for bad_req in (None, 1, True, "req-00", "req-13", "REQ-01", "r1", ""):
        with pytest.raises(mod.BadRequirementError):
            p.assess("merchant-1", seq, requirement=bad_req)
        seq += 1
    for bad_finding in (None, 1, True, "pass", "failed", ""):
        with pytest.raises(mod.BadFindingError):
            p.assess("merchant-1", seq, finding=bad_finding)
        seq += 1
    for bad_sev in (None, 1, True, "lowr", "CRITICAL", ""):
        with pytest.raises(mod.BadSeverityError):
            p.assess("merchant-1", seq, severity=bad_sev)
        seq += 1
    for bad_id in (None, 1, True, "", "has space"):
        with pytest.raises(mod.BadIdError):
            p.assess(bad_id, seq)
        seq += 1
    # failed mutations burned their seqs: 1 rejected row each
    assert p.stats(seq)["rejected"] == 1 + 8 + 6 + 6 + 5


def test_all_twelve_requirements_accepted(p, mod):
    p.register_merchant("merchant-1", "level-1", 1)
    for i in range(1, 13):
        rec = p.assess("merchant-1", 1 + i, requirement=f"req-{i:02d}",
                       finding="compliant")
        assert rec.verify()
    report = p.validate("merchant-1", 14)
    assert len(report.requirements_covered) == 12
    assert report.validated is True
    assert report.verify()


def test_remediate_roundtrip_chain_and_refusals(p, mod):
    p.register_merchant("merchant-1", "level-1", 1)
    a1 = p.assess("merchant-1", 2, requirement="req-04",
                  finding="non-compliant", severity="high")
    r1 = p.remediate(a1.assessment_id, 3, action="encrypt",
                     plan_digest=good_digest("plan"))
    assert r1.remediation_id == "rem-1"
    assert r1.verify()
    r2 = p.remediate(a1.assessment_id, 4, action="rotate-keys")
    assert r2.remediation_id == "rem-2"
    assert p.remediations_for(a1.assessment_id, 5) == ("rem-1", "rem-2")
    assert p.remediation_record("rem-1", 6) is r1
    # addressed findings refuse remediation fail-closed
    seq = 7
    for addressed in ("compliant", "not-applicable", "in-place-with-ccw"):
        a = p.assess("merchant-1", seq, requirement="req-01",
                     finding=addressed)
        seq += 1
        with pytest.raises(mod.RemediationNotNeededError):
            p.remediate(a.assessment_id, seq)
        seq += 1
    # unknown assessment / bad action refused
    with pytest.raises(mod.UnknownAssessmentError):
        p.remediate("asm-999", seq)
    seq += 1
    with pytest.raises(mod.BadRemediationError):
        p.remediate(a1.assessment_id, seq, action="hack")
    seq += 1
    assert p.stats(seq)["rejected"] == 5
    assert p.stats(seq)["remediations"] == 2


def test_validate_requires_full_coverage(p, mod):
    p.register_merchant("m1", "level-2", 1)
    for i in range(1, 6):
        p.assess("m1", 1 + i, requirement=f"req-{i:02d}", finding="compliant")
    report = p.validate("m1", 7)
    assert report.validated is False  # only 5 of 12 covered
    assert len(report.requirements_covered) == 5
    assert report.n_assessments == 5
    assert report.verify()


def test_validate_open_finding_blocks_and_remediate_clears(p, mod):
    p.register_merchant("m1", "level-1", 1)
    seq = 2
    for i in range(1, 13):
        p.assess("m1", seq, requirement=f"req-{i:02d}",
                 finding="non-compliant" if i == 7 else "compliant",
                 severity="high" if i == 7 else "low")
        seq += 1
    report = p.validate("m1", seq)
    assert report.validated is False  # open non-compliant finding
    assert report.findings == (("compliant", 11), ("non-compliant", 1))
    p.remediate("asm-7", seq + 1, action="reconfigure")
    report2 = p.validate("m1", seq + 2)
    assert report2.validated is True
    assert report2.remediated_assessments == ("asm-7",)
    assert report2.verify()
    with pytest.raises(mod.UnknownMerchantError):
        p.validate("ghost", seq + 3)


def test_validate_read_purity_and_views(p, mod):
    p.register_merchant("m1", "level-3", 1)
    a = p.assess("m1", 2, requirement="req-01", finding="compliant")
    before = p.stats(3)
    r1 = p.validate("m1", 4)
    r2 = p.validate("m1", 4)  # same seq twice: no consumption
    assert r1.digest == r2.digest
    assert p.merchant_record("m1", 5) is not None
    assert p.merchant_ids(6) == ("m1",)
    assert p.assessment_record(a.assessment_id, 7) is a
    assert p.assessment_ids(8) == ("asm-1",)
    assert p.assessments_for("m1", 9) == ("asm-1",)
    assert p.stats(10) == before  # no new audit rows from the reads
    assert r1.validated is False  # partial coverage: data, not raised


def test_seq_discipline(p, mod):
    p.register_merchant("m1", "level-1", 1)
    with pytest.raises(mod.SeqOrderError):  # rewind raises bare
        p.register_merchant("m2", "level-1", 1)
    assert p.stats(2)["rejected"] == 0  # bare rewind books no row
    for bad_seq in (None, True, "3", 3.0, -1):
        with pytest.raises(mod.SeqOrderError):
            p.register_merchant("m2", "level-1", bad_seq)
    p.register_merchant("m2", "level-1", 3)  # seq 3 still free
    assert p.stats(4)["merchants"] == 2


def test_audit_shapes_leak_ban_and_bad_kind(p, mod):
    p = mod.PCIDSS()
    p.register_merchant("m1", "level-1", 1)
    p.assess("m1", 2, requirement="req-01")
    rows = p.audit_log(3)
    assert len(rows) == 2
    assert rows[0]["audit_version"] == "audit.ndjson/1"
    assert rows[0]["schema"] == "northstar.pci-dss.v1"
    assert rows[0]["kind"] == "pci-dss.merchant-registered"
    assert rows[1]["kind"] == "pci-dss.assessed"
    with pytest.raises(mod.AuditKindError):
        mod.pci_dss_audit_event("bogus", {}, 4)
    for banned in ("evidence", "pan", "cardholder", "content"):
        with pytest.raises(mod.AuditKindError):
            mod.pci_dss_audit_event("assessed", {banned: "x"}, 4)


def test_cross_instance_determinism_tamper_and_frozen(p, mod):
    g1, g2 = mod.PCIDSS(), mod.PCIDSS()
    g1.register_merchant("m1", "level-1", 1)
    g2.register_merchant("m1", "level-1", 1)
    a1 = g1.assess("m1", 2, requirement="req-01")
    a2 = g2.assess("m1", 2, requirement="req-01")
    assert a1.digest == a2.digest  # cross-instance determinism
    object.__setattr__(a1, "finding", "non-compliant")
    assert a1.verify() is False  # tamper breaks the pin
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        a1.finding = "x"  # frozen-ness


def test_concurrency_smoke_and_main(p, mod):
    p = mod.PCIDSS()
    p.register_merchant("m1", "level-1", 1)
    p.assess("m1", 2, requirement="req-01")
    errs = []

    def read(i):
        try:
            p.validate("m1", 100 + i)
            p.stats(200 + i)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    threads = [threading.Thread(target=read, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    out = subprocess.run(
        [sys.executable, str(MODULE_PATH)], capture_output=True, text=True,
        timeout=60)
    assert out.returncode == 0
    assert "pci-dss OK: register, assess, remediate, validate, pins, audit" \
        in out.stdout
