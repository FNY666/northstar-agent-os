"""Tests for the NIST CSF 2.0 assessment decision ledger (16 tests)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "nist_csf.py"


def load_module():
    """Import the module standalone via importlib (frozen dataclasses
    need the module registered in sys.modules first)."""
    import importlib.util

    sys.modules.pop("nist_csf", None)
    spec = importlib.util.spec_from_file_location("nist_csf", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["nist_csf"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def c(mod):
    return mod.NISTCSF()


def good_digest(label="nist-csf"):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def all_tiers(tier):
    return tuple((fn, tier) for fn in
                 ("govern", "identify", "protect", "detect",
                  "respond", "recover"))


def test_version_and_schema_pins():
    mod = load_module()
    assert mod.VERSION == "nist-csf.v1"
    assert mod.SCHEMA == "northstar.nist-csf.v1"


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


def test_profile_roundtrip_verify_and_views(c, mod):
    rec = c.profile("p-current", "current", 1,
                    function_tiers=all_tiers(2))
    assert rec.profile_id == "p-current"
    assert rec.profile_kind == "current"
    assert rec.tier_for("govern") == 2
    assert rec.verify()
    assert c.profile_record("p-current", 2) is rec
    assert c.profile_ids(3) == ("p-current",)
    # duplicate refused fail-closed
    with pytest.raises(mod.DuplicateProfileError):
        c.profile("p-current", "current", 4,
                  function_tiers=all_tiers(1))
    assert c.stats(5)["rejected"] == 1


def test_profile_bad_inputs_and_vocabulary(c, mod):
    seq = 100
    for bad in (None, 1, True, b"x", "", "has space", "x" * 257):
        with pytest.raises(mod.BadIdError):
            c.profile(bad, "current", seq, function_tiers=all_tiers(1))
        seq += 1
    for bad in ("future", "", None, 1, True):
        with pytest.raises(mod.BadProfileKindError):
            c.profile(f"p-bad-{seq}", bad, seq, function_tiers=all_tiers(1))
        seq += 1
    # bad digest refused
    with pytest.raises(mod.BadDigestError):
        c.profile("p-dd", "current", seq, function_tiers=all_tiers(1),
                  description_digest="not-a-digest")
    seq += 1
    # both kinds accepted
    c.profile("p-cur", "current", seq, function_tiers=all_tiers(1))
    seq += 1
    c.profile("p-tgt", "target", seq, function_tiers=all_tiers(4))
    seq += 1
    assert c.stats(seq)["profiles"] == 2


def test_profile_function_tiers_validation(c, mod):
    seq = 1
    # missing functions refused
    with pytest.raises(mod.BadFunctionTiersError):
        c.profile("p-miss", "current", seq,
                  function_tiers=(("govern", 1), ("protect", 2)))
    seq += 1
    # duplicate function refused
    with pytest.raises(mod.BadFunctionTiersError):
        c.profile("p-dup", "current", seq,
                  function_tiers=all_tiers(1) + (("govern", 3),))
    seq += 1
    # bad function name refused
    with pytest.raises(mod.BadFunctionError):
        c.profile("p-bfn", "current", seq,
                  function_tiers=(("governance", 1),) + all_tiers(2)[1:])
    seq += 1
    # bad tier refused
    with pytest.raises(mod.BadTierError):
        c.profile("p-bt", "current", seq,
                  function_tiers=(("govern", 5),) + all_tiers(2)[1:])
    seq += 1
    # tier bool refused
    with pytest.raises(mod.BadTierError):
        c.profile("p-bb", "current", seq,
                  function_tiers=(("govern", True),) + all_tiers(2)[1:])
    seq += 1
    # not a sequence refused
    with pytest.raises(mod.BadFunctionTiersError):
        c.profile("p-ns", "current", seq, function_tiers="govern")
    seq += 1
    # malformed entries refused
    with pytest.raises(mod.BadFunctionTiersError):
        c.profile("p-me", "current", seq,
                  function_tiers=(("govern", 1, "extra"),) + all_tiers(2)[1:])
    seq += 1
    assert c.stats(seq)["rejected"] == 7
    # unknown profile lookup refused
    with pytest.raises(mod.UnknownProfileError):
        c.profile_record("nope", seq)


def test_assess_roundtrip_verify_and_views(c, mod):
    rec = c.assess("govern", 2, 1, evidence_digest=good_digest("e1"))
    assert rec.assessment_id == "asm-1"
    assert rec.function == "govern"
    assert rec.tier == 2
    assert rec.verify()
    assert c.assessment_record("asm-1", 2) is rec
    assert c.assessment_ids(3) == ("asm-1",)
    assert c.assessments_for("govern", 4) == ("asm-1",)
    assert c.assessments_for("protect", 5) == ()


def test_assess_bad_inputs_and_vocabulary(c, mod):
    seq = 1
    for bad in ("governance", "", None, 1, True, b"govern"):
        with pytest.raises(mod.BadFunctionError):
            c.assess(bad, 2, seq)
        seq += 1
    for bad in (0, 5, True, "3", None, 2.0):
        with pytest.raises(mod.BadTierError):
            c.assess("identify", bad, seq)
        seq += 1
    with pytest.raises(mod.BadDigestError):
        c.assess("protect", 1, seq, evidence_digest="nope")
    seq += 1
    # all 6 functions x all 4 tiers accepted
    for fn in ("govern", "identify", "protect", "detect", "respond",
               "recover"):
        for tier in (1, 2, 3, 4):
            c.assess(fn, tier, seq)
            seq += 1
    assert c.stats(seq)["assessments"] == 24
    # unknown assessment lookup refused
    with pytest.raises(mod.UnknownAssessmentError):
        c.assessment_record("asm-999", seq)
    # bad function in view refused
    with pytest.raises(mod.BadFunctionError):
        c.assessments_for("governance", seq)


def test_improve_roundtrip_verify_and_chain(c, mod):
    c.assess("detect", 1, 1)
    c.assess("detect", 2, 2)
    r1 = c.improve("detect", 3, 3, action="implement-control")
    assert r1.improvement_id == "imp-1"
    assert r1.function == "detect"
    assert r1.target_tier == 3
    assert r1.action == "implement-control"
    assert r1.verify()
    r2 = c.improve("detect", 4, 4, action="train",
                   plan_digest=good_digest("plan"))
    assert r2.improvement_id == "imp-2"
    assert c.improvements_for("detect", 5) == ("imp-1", "imp-2")
    assert c.improvement_record("imp-1", 6) is r1


def test_improve_refusals(c, mod):
    # unassessed function refused fail-closed
    with pytest.raises(mod.UnassessedFunctionError):
        c.improve("respond", 2, 1)
    # bad action vocabulary refused
    c.assess("respond", 1, 2)
    with pytest.raises(mod.BadActionError):
        c.improve("respond", 2, 3, action="pray")
    # target tier not above latest assessed tier refused
    with pytest.raises(mod.ImprovementNotNeededError):
        c.improve("respond", 1, 4)
    # equal tier refused
    with pytest.raises(mod.ImprovementNotNeededError):
        c.improve("respond", 1, 5)
    # bad tier refused
    with pytest.raises(mod.BadTierError):
        c.improve("respond", 9, 6)
    # bad digest refused
    with pytest.raises(mod.BadDigestError):
        c.improve("respond", 2, 7, plan_digest="bad")
    # bad function refused
    with pytest.raises(mod.BadFunctionError):
        c.improve("nope", 2, 8)
    # all 7 actions accepted
    for i, action in enumerate(("implement-control", "remediate", "document",
                               "train", "procure", "reassess",
                               "accept-risk")):
        c.assess("recover", 1, 10 + i * 3)
        c.improve("recover", 2, 11 + i * 3, action=action)
    assert c.stats(32)["rejected"] == 7
    # unknown improvement lookup refused
    with pytest.raises(mod.UnknownAssessmentError):
        c.improvement_record("imp-999", 33)


def test_gap_report_math_and_purity(c, mod):
    c.profile("cur", "current", 1, function_tiers=all_tiers(1))
    c.profile("tgt", "target", 2, function_tiers=all_tiers(3))
    c.assess("govern", 2, 3)  # profile baseline still governs
    report = c.gap(4)
    assert report.verify()
    for fn in ("govern", "identify", "protect", "detect", "respond",
               "recover"):
        assert report.gap_for(fn) == 2  # 3 - 1
    assert len(report.gaps) == 6
    # gap() is a pure read: same seq twice, no audit rows, no seq consumed
    before = len(c.audit_log(5))
    r2 = c.gap(5)
    assert r2.gap_for("protect") == 2
    assert len(c.audit_log(5)) == before
    # no profiles / no assessments -> zero gaps, still pure data
    c2 = mod.NISTCSF()
    empty = c2.gap(1)
    assert all(g == 0 for _, g in empty.gaps)
    assert empty.verify()


def test_gap_assessment_baseline_without_profiles(c, mod):
    c.assess("protect", 2, 1)
    c.assess("identify", 3, 2)
    c.profile("tgt", "target", 3, function_tiers=all_tiers(4))
    report = c.gap(4)
    assert report.gap_for("protect") == 2   # 4 - 2
    assert report.gap_for("identify") == 1  # 4 - 3
    assert report.gap_for("govern") == 4    # 4 - 0 (no data)


def test_seq_discipline_and_failed_mutations_burn(c, mod):
    c.profile("p", "current", 1, function_tiers=all_tiers(1))
    # rewind raises bare: no rejected row, seq still free
    before = c.stats(2)["rejected"]
    with pytest.raises(mod.SeqOrderError):
        c.profile("p2", "current", 1, function_tiers=all_tiers(1))
    assert c.stats(2)["rejected"] == before
    # same seq reused still fails
    with pytest.raises(mod.SeqOrderError):
        c.assess("govern", 1, 1)
    # malformed seqs raise bare
    for bad in (True, "1", None, -1, 1.5):
        with pytest.raises(mod.SeqOrderError):
            c.assess("govern", 1, bad)
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(mod.BadFunctionError):
        c.assess("nope", 1, 2)
    assert c.stats(3)["rejected"] == 1
    with pytest.raises(mod.SeqOrderError):
        c.assess("govern", 1, 2)  # seq 2 already burned
    # view with malformed seq raises bare, no rows consumed
    n_audit = len(c.audit_log(3))
    with pytest.raises(mod.SeqOrderError):
        c.stats("3")
    assert len(c.audit_log(3)) == n_audit


def test_audit_shapes_and_leak_ban(c, mod):
    c.profile("p", "target", 1, function_tiers=all_tiers(2))
    c.assess("govern", 1, 2, evidence_digest=good_digest())
    c.improve("govern", 2, 3)
    rows = c.audit_log(4)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["nist-csf.profile-registered", "nist-csf.assessed",
                     "nist-csf.improved"]
    for r in rows:
        assert r["audit_version"] == "audit.ndjson/1"
        assert r["schema"] == "northstar.nist-csf.v1"
        assert r["version"] == "nist-csf.v1"
    # raw-text keys banned at the audit boundary
    with pytest.raises(mod.AuditKindError):
        mod.nist_csf_audit_event("assessed", {"evidence": "raw-text"}, 10)
    with pytest.raises(mod.AuditKindError):
        mod.nist_csf_audit_event("nope", {}, 10)
    # no raw material leaks into any audit row
    blob = repr(rows)
    assert "raw-text" not in blob


def test_cross_instance_determinism_and_tamper(c, mod):
    c1, c2 = mod.NISTCSF(), mod.NISTCSF()
    r1 = c1.profile("p", "current", 1, function_tiers=all_tiers(2))
    r2 = c2.profile("p", "current", 1, function_tiers=all_tiers(2))
    assert r1.digest == r2.digest
    a1 = c1.assess("govern", 2, 2)
    a2 = c2.assess("govern", 2, 2)
    assert a1.digest == a2.digest
    assert a1.verify()
    # tamper breaks verify() as data, never raises
    object.__setattr__(a1, "tier", 4)
    assert a1.verify() is False
    # gap reports deterministic too
    c1.profile("t", "target", 3, function_tiers=all_tiers(4))
    c2.profile("t", "target", 3, function_tiers=all_tiers(4))
    g1, g2 = c1.gap(4), c2.gap(4)
    assert g1.digest == g2.digest and g1.verify()


def test_frozen_records_and_concurrent_reads(c, mod):
    c.assess("govern", 1, 1)
    rec = c.assessment_record("asm-1", 2)
    with pytest.raises(Exception):
        rec.tier = 4
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.function = "protect"
    # 4-thread read smoke
    errors = []

    def reader():
        try:
            for _ in range(50):
                c.assessment_record("asm-1", 3)
                c.gap(3)
                c.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_main_selfcheck():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "nist-csf OK: profile, assess, improve, gap, pins, audit" in \
        result.stdout
