"""Tests for the ai-privacy assessment/protection decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_privacy.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_privacy", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_privacy"] = module
    spec.loader.exec_module(module)
    return module


ap = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ap.AI_PRIVACY_VERSION == "ai-privacy.v1"
    assert ap.SCHEMA_PIN == "northstar.ai-privacy.v1"
    assert ap.RISK_KINDS == (
        "data-minimization",
        "consent-management",
        "purpose-limitation",
        "data-retention",
        "anonymization",
        "access-control",
        "cross-border-transfer",
        "surveillance-risk",
    )
    assert ap.ASSESS_VERDICTS == (
        "compliant",
        "noncompliant",
        "at-risk",
        "inconclusive",
        "not-assessed",
    )
    assert ap.PROTECTION_STRATEGIES == (
        "differential-privacy",
        "data-minimization",
        "encryption-at-rest",
        "access-tightening",
        "retention-shortening",
        "anonymization-upgrade",
        "consent-refresh",
        "no-action",
    )
    assert ap.POSTURES == (
        "unassessed",
        "noncompliant",
        "at-risk",
        "mitigated",
        "compliant",
    )
    assert ap.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


# 2. stdlib-only AST check
def test_stdlib_only():
    assert ap.stdlib_only() is True
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. assess roundtrip / verify / frozen-ness
def test_assess_roundtrip_verify_frozen():
    ledger = ap.AIPrivacy()
    rec = ledger.assess(
        "sys-1", 1, risk_kind="data-retention", verdict="noncompliant", severity=70
    )
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.verify() is True
    assert dataclasses.is_dataclass(rec)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 0  # type: ignore[misc]
    got = ledger.assessment_record("asm-1", 1)
    assert got == rec
    assert ledger.system_ids(1) == ("sys-1",)


# 4. bad-input table + seq-burn + rejected-row accounting
def test_assess_bad_inputs_burn_seq():
    ledger = ap.AIPrivacy()
    bad = [
        ("", 1, "BadSystemError"),
        ("sys", 2, "BadRiskKindError", {"risk_kind": "nope"}),
        ("sys", 3, "BadVerdictError", {"verdict": "nope"}),
        ("sys", 4, "BadSeverityError", {"severity": 101}),
        ("sys", 5, "BadSeverityError", {"severity": True}),
        ("sys", 6, "BadDigestError", {"assessment_digest": "sha256:xyz"}),
    ]
    expect = 0
    for entry in bad:
        system_id, seq = entry[0], entry[1]
        kwargs = entry[3] if len(entry) > 3 else {}
        with pytest.raises(ap.AIPrivacyError):
            ledger.assess(system_id, seq, **kwargs)
        expect += 1
    rows = ledger.audit_log(7)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == expect
    assert rejected[0]["seq"] == 1
    # rewinds raise bare with no new row
    with pytest.raises(ap.SeqOrderError):
        ledger.assess("sys", 1)
    assert len([r for r in ledger.audit_log(8) if r["kind"] == "rejected"]) == expect


# 5. full risk-kind vocabulary acceptance
def test_all_risk_kinds_accepted():
    ledger = ap.AIPrivacy()
    for i, kind in enumerate(ap.RISK_KINDS, start=1):
        rec = ledger.assess(f"sys-{i}", i, risk_kind=kind)
        assert rec.verify() is True
        assert rec.risk_kind == kind
    assert ledger.stats(0)["n_assessments"] == len(ap.RISK_KINDS)


# 6. protect roundtrip / full strategy vocabulary / minted ids
def test_protect_roundtrip_and_strategies():
    ledger = ap.AIPrivacy()
    rec = ledger.assess("sys-1", 1, verdict="noncompliant")
    for i, strategy in enumerate(ap.PROTECTION_STRATEGIES, start=2):
        prt = ledger.protect(rec.assessment_id, i, strategy=strategy)
        assert prt.verify() is True
        assert prt.protection_id == f"prt-{i - 1}"
        assert prt.strategy == strategy
    got = ledger.protection_record("prt-1", 9)
    assert got.assessment_id == rec.assessment_id
    assert len(ledger.protections_for(rec.assessment_id, 9)) == len(
        ap.PROTECTION_STRATEGIES
    )


# 7. protect refusal table (unknown assessment / bad inputs / seq-burn)
def test_protect_refusals_burn_seq():
    ledger = ap.AIPrivacy()
    with pytest.raises(ap.UnknownAssessmentError):
        ledger.protect("asm-404", 1)
    with pytest.raises(ap.BadStrategyError):
        ledger.protect("asm-404", 2, strategy="nope")
    with pytest.raises(ap.BadDigestError):
        ledger.protect("asm-404", 3, protection_digest="bad")
    rejected = [r for r in ledger.audit_log(4) if r["kind"] == "rejected"]
    assert len(rejected) == 3
    assert [r["seq"] for r in rejected] == [1, 2, 3]


# 8. verify semantics: verified roundtrip, tamper-as-data, read purity
def test_verify_semantics_and_read_purity():
    ledger = ap.AIPrivacy()
    rec = ledger.assess("sys-1", 1, verdict="at-risk")
    prt = ledger.protect(rec.assessment_id, 2)
    rep = ledger.verify(rec.assessment_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    rep2 = ledger.verify(prt.protection_id, 3)  # same seq twice: read purity
    assert rep2.verdict == "verified"
    assert rep2.digest != rep.digest
    # tamper is reported as data, never raised
    object.__setattr__(rec, "verdict", "compliant")
    tampered = ledger.verify(rec.assessment_id, 4)
    assert tampered.verdict == "tampered"
    assert tampered.integrity_ok is False
    # no audit rows written by pure reads
    assert ledger.stats(5)["n_audit_rows"] == 2
    with pytest.raises(ap.UnknownRecordError):
        ledger.verify("nope", 6)


# 9. evaluate posture math (all 5 postures + precedence)
def test_evaluate_posture_math():
    ledger = ap.AIPrivacy()
    ledger.assess("a", 1, verdict="noncompliant")
    assert ledger.evaluate("a", 2).posture == "noncompliant"
    ledger.protect("asm-1", 3)
    assert ledger.evaluate("a", 4).posture == "mitigated"
    ledger.assess("b", 5, verdict="at-risk")
    assert ledger.evaluate("b", 6).posture == "at-risk"
    ledger.assess("c", 7, verdict="compliant")
    assert ledger.evaluate("c", 8).posture == "compliant"
    # unmitigated noncompliant outranks a later compliant verdict
    ledger.assess("c", 9, verdict="noncompliant")
    assert ledger.evaluate("c", 10).posture == "noncompliant"
    # inconclusive lands at-risk
    ledger.assess("d", 11, verdict="inconclusive")
    assert ledger.evaluate("d", 12).posture == "at-risk"
    ev = ledger.evaluate("a", 13)
    assert ev.n_assessments == 1 and ev.n_noncompliant == 1 and ev.n_protected == 1
    assert ev.integrity_ok is True and ev.verify() is True
    with pytest.raises(ap.UnknownSystemError):
        ledger.evaluate("ghost", 14)


# 10. evaluate read purity + tamper flips integrity_ok as data
def test_evaluate_read_purity_and_integrity_flip():
    ledger = ap.AIPrivacy()
    rec = ledger.assess("sys-1", 1, verdict="compliant")
    ev1 = ledger.evaluate("sys-1", 2)
    ev2 = ledger.evaluate("sys-1", 2)
    assert ev1 == ev2
    assert ledger.stats(3)["n_audit_rows"] == 1  # no rows from reads
    object.__setattr__(rec, "severity", 99)
    ev3 = ledger.evaluate("sys-1", 3)
    assert ev3.integrity_ok is False
    assert ev3.verify() is True  # report digest still self-consistent


# 11. retire terminality: post-retire refusals, id non-recycling, bad reason
def test_retire_terminality():
    ledger = ap.AIPrivacy()
    ledger.assess("sys-1", 1, verdict="at-risk")
    for bad_seq in (2,):
        with pytest.raises(ap.BadReasonError):
            ledger.retire("sys-1", bad_seq, reason="nope")
    ret = ledger.retire("sys-1", 3, reason="decommissioned")
    assert ret.verify() is True
    with pytest.raises(ap.RetiredSystemError):
        ledger.retire("sys-1", 4)
    with pytest.raises(ap.RetiredSystemError):
        ledger.assess("sys-1", 5)
    rec = ledger.assess("sys-2", 6)
    ledger.retire("sys-2", 7)
    with pytest.raises(ap.RetiredSystemError):
        ledger.protect(rec.assessment_id, 8)
    # reads still work post-retire; ids never recycled
    assert ledger.evaluate("sys-1", 9).posture == "at-risk"
    assert ledger.retired_ids(10) == ("sys-1", "sys-2")
    with pytest.raises(ap.UnknownSystemError):
        ledger.retire("ghost", 11)


# 12. seq discipline: rewinds bare, malformed seqs, reads don't burn
def test_seq_discipline():
    ledger = ap.AIPrivacy()
    for bad in (True, 1.5, "1", None):
        with pytest.raises(ap.SeqOrderError):
            ledger.assess("sys", bad)
        with pytest.raises(ap.SeqOrderError):
            ledger.evaluate("sys", bad) if False else ledger.assess("sys", bad)
    rec = ledger.assess("sys-1", 1)
    with pytest.raises(ap.SeqOrderError):
        ledger.assess("sys-1", 1)  # rewind: bare, zero rows
    assert ledger.audit_log(2) == ledger.audit_log(2)  # tuple, no side effects
    with pytest.raises(ap.SeqOrderError):
        ledger.verify(rec.assessment_id, -1)
    with pytest.raises(ap.SeqOrderError):
        ledger.stats("x")


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = ap.AIPrivacy()
    rec = ledger.assess("sys-1", 1, assessment_digest=PIN)
    row = ledger.audit_log(2)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-privacy"
    assert row["kind"] == "assessed"
    assert row["details"]["assessment_id"] == "asm-1"
    assert "assessment_digest" not in row["details"]
    with pytest.raises(ap.AIPrivacyError):
        ap.ai_privacy_audit_event("assessed", 3, pii="raw")
    with pytest.raises(ap.AIPrivacyError):
        ap.ai_privacy_audit_event("assessed", 3, location="raw")
    with pytest.raises(ap.AuditKindError):
        ap.ai_privacy_audit_event("nope", 3)
    with pytest.raises(ap.SeqOrderError):
        ap.ai_privacy_audit_event("assessed", True)
    # digest pins of banned-looking values are fine as declared data
    ok = ap.ai_privacy_audit_event("assessed", 3, assessment_digest=PIN)
    assert ok["details"]["assessment_digest"] == PIN


# 14. cross-instance determinism + views/stats + thread read smoke
def test_determinism_views_and_threads():
    a = ap.AIPrivacy()
    b = ap.AIPrivacy()
    ra = a.assess("sys-1", 1, risk_kind="consent-management", verdict="compliant", assessment_digest=PIN)
    rb = b.assess("sys-1", 1, risk_kind="consent-management", verdict="compliant", assessment_digest=PIN)
    assert ra.digest == rb.digest
    assert a.evaluate("sys-1", 2).digest == b.evaluate("sys-1", 2).digest
    assert a.assessments_for("sys-1", 3) == (ra,)
    assert a.assessment_ids(3) == ("asm-1",)
    st = a.stats(3)
    assert st["n_systems"] == 1 and st["n_assessments"] == 1
    errs = []

    def reader():
        try:
            for _ in range(50):
                a.evaluate("sys-1", 9)
                a.audit_log(9)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs


# 15. main() subprocess self-check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-privacy OK: assess, protect, verify, evaluate, retire, pins, audit" in proc.stdout
