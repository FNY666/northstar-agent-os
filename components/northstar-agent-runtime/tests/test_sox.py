"""Tests for the SOX compliance decision ledger (15 tests)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "sox.py"


def load_module():
    """Import the module standalone via importlib (frozen dataclasses
    need the module registered in sys.modules first)."""
    import importlib.util

    sys.modules.pop("sox", None)
    spec = importlib.util.spec_from_file_location("sox", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["sox"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def s(mod):
    return mod.SOX()


def good_digest(label="sox"):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def test_version_and_schema_pins():
    mod = load_module()
    assert mod.VERSION == "sox.v1"
    assert mod.SCHEMA == "northstar.sox.v1"


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
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


def test_assess_roundtrip_and_verify(mod, s):
    rec = s.assess("fy2026", 1, control_area="it-general-controls",
                   finding="material-weakness", control_owner="cio",
                   evidence_digest=good_digest("ev"))
    assert rec.assessment_id == "asmt-1"
    assert rec.verify()
    assert rec.as_dict()["finding"] == "material-weakness"
    fetched = s.assessment_record("asmt-1", 2)
    assert fetched.digest == rec.digest
    assert fetched.verify()


def test_assess_bad_inputs_burn_seq(mod, s):
    bad_cases = [
        ("", "financial-reporting", "effective"),          # empty scope
        ("fy 2026", "financial-reporting", "effective"),  # whitespace
        ("fy2026", "bogus-area", "effective"),            # bad control area
        ("fy2026", "financial-reporting", "bogus"),       # bad finding
        ("fy2026", "financial-reporting", "effective", "not hex"),  # bad digest
    ]
    seq = 1
    rejected = 0
    for case in bad_cases:
        with pytest.raises(mod.SOXError):
            if len(case) == 4:
                s.assess(case[0], seq, control_area=case[1],
                         finding=case[2], evidence_digest=case[3])
            else:
                s.assess(case[0], seq, control_area=case[1],
                         finding=case[2])
        seq += 1
        rejected += 1
    assert s.stats(seq)["rejected"] == rejected
    log = s.audit_log(seq + 1)
    kinds = [row["kind"] for row in log]
    assert kinds.count("sox.rejected") == rejected


def test_assess_owner_validation(mod, s):
    with pytest.raises(mod.BadIdError):
        s.assess("fy2026", 1, control_owner="cio team")  # whitespace
    assert s.stats(2)["rejected"] == 1


def test_remediate_roundtrip_and_chain(mod, s):
    a = s.assess("fy2026", 1, finding="significant-deficiency")
    r1 = s.remediate(a.assessment_id, 2, action="redesign")
    r2 = s.remediate(a.assessment_id, 3, action="automate")
    assert r1.remediation_id == "rmd-1"
    assert r2.remediation_id == "rmd-2"
    assert r1.verify() and r2.verify()
    assert s.remediations_for(a.assessment_id, 4) == ("rmd-1", "rmd-2")


def test_remediate_refusals(mod, s):
    a_eff = s.assess("fy2026", 1, finding="effective")
    with pytest.raises(mod.RemediationNotNeededError):
        s.remediate(a_eff.assessment_id, 2)
    with pytest.raises(mod.UnknownAssessmentError):
        s.remediate("asmt-999", 3)
    a2 = s.assess("fy2026", 4, finding="deficient")
    with pytest.raises(mod.BadActionError):
        s.remediate(a2.assessment_id, 5, action="bribe-auditor")
    assert s.stats(6)["rejected"] == 3


def test_attest_opinions(mod, s):
    # adverse: unremediated material weakness
    s.assess("scope-a", 1, finding="material-weakness")
    assert s.attest("scope-a", 2).opinion == "adverse"
    # qualified: unremediated significant deficiency
    s.assess("scope-b", 3, finding="significant-deficiency")
    assert s.attest("scope-b", 4).opinion == "qualified"
    # unqualified: all findings effective
    s.assess("scope-c", 5, finding="effective")
    s.assess("scope-c", 6, finding="effective")
    assert s.attest("scope-c", 7).opinion == "unqualified"
    # unqualified: remediation booked for a deficiency
    d = s.assess("scope-d", 8, finding="deficient")
    s.remediate(d.assessment_id, 9)
    assert s.attest("scope-d", 10).opinion == "unqualified"
    # not-assessed: scope with no assessments
    rep = s.attest("scope-empty", 11)
    assert rep.opinion == "not-assessed"
    assert rep.n_assessments == 0
    assert rep.verify()


def test_attest_read_purity(mod, s):
    s.assess("fy2026", 1, finding="effective")
    r1 = s.attest("fy2026", 2)
    r2 = s.attest("fy2026", 2)  # same seq twice is fine for reads
    assert r1.digest == r2.digest
    assert s.attest("fy2026", 3).opinion == "unqualified"
    log = s.audit_log(4)
    assert all(row["kind"] != "sox.rejected" for row in log)
    assert s.stats(5)["rejected"] == 0


def test_seq_discipline(mod, s):
    s.assess("fy2026", 1)
    with pytest.raises(mod.SeqOrderError):  # rewind raises bare
        s.assess("fy2026", 1)
    with pytest.raises(mod.SeqOrderError):  # bool seq
        s.assess("fy2026", True)
    with pytest.raises(mod.SeqOrderError):  # negative seq
        s.attest("fy2026", -2)
    with pytest.raises(mod.SeqOrderError):  # str seq
        s.attest("fy2026", "2")
    # bare raises consume nothing: next valid seq still 2
    s.attest("fy2026", 2)
    assert s.stats(3)["rejected"] == 0


def test_audit_shapes_and_leak_ban(mod):
    s = mod.SOX()
    a = s.assess("fy2026", 1, control_area="financial-reporting",
                 finding="deficient", evidence_digest=good_digest("ev"))
    s.remediate(a.assessment_id, 2, action="strengthen")
    log = s.audit_log(3)
    assert len(log) == 2
    for row in log:
        assert row["audit_version"] == "audit.ndjson/1"
        assert row["schema"] == "northstar.sox.v1"
        assert row["version"] == "sox.v1"
        assert row["kind"] in ("sox.assessed", "sox.remediated")
    banned = {"content", "text", "payload", "raw", "evidence",
              "description", "notes", "message", "plan", "title",
              "summary", "opinion_text"}
    for row in log:
        assert not (banned & set(row["detail"].keys()))
    with pytest.raises(mod.AuditKindError):
        mod.sox_audit_event("bogus-kind", {}, 4)
    with pytest.raises(mod.AuditKindError):
        mod.sox_audit_event("assessed", {"evidence": "x"}, 4)


def test_digest_determinism_and_tamper(mod):
    s1, s2 = mod.SOX(), mod.SOX()
    a1 = s1.assess("fy2026", 1, finding="deficient")
    a2 = s2.assess("fy2026", 1, finding="deficient")
    assert a1.digest == a2.digest  # cross-instance determinism
    r1 = s1.attest("fy2026", 2)
    r2 = s2.attest("fy2026", 2)
    assert r1.digest == r2.digest
    # tamper breaks verify()
    object.__setattr__(a1, "finding", "effective")
    assert not a1.verify()


def test_views_and_stats(mod, s):
    s.assess("fy2026", 1, finding="effective")
    s.assess("fy2026", 2, finding="deficient")
    assert s.assessment_ids(3) == ("asmt-1", "asmt-2")
    assert s.assessments_for("fy2026", 4) == ("asmt-1", "asmt-2")
    assert s.assessments_for("other", 5) == ()
    stats = s.stats(6)
    assert stats == {"assessments": 2, "remediations": 0, "rejected": 0}
    with pytest.raises(mod.UnknownAssessmentError):
        s.assessment_record("asmt-999", 7)
    with pytest.raises(mod.UnknownAssessmentError):
        s.remediations_for("asmt-999", 8)


def test_frozen_and_thread_safe(mod, s):
    a = s.assess("fy2026", 1, finding="deficient")
    with pytest.raises(Exception):
        a.finding = "effective"  # frozen dataclass
    errors = []

    def reader():
        try:
            for i in range(50):
                s.attest("fy2026", 1000 + i)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == \
        "sox OK: assess, remediate, attest, pins, audit"
