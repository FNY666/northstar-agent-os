"""Tests for risk_assessment: identify / score / mitigate ledger."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from risk_assessment import (
    RISK_ASSESSMENT_SCHEMA,
    RISK_ASSESSMENT_VERSION,
    BadCategoryError,
    BadDigestError,
    BadRiskError,
    BadScoreError,
    BadStrategyError,
    RiskAssessment,
    RiskAssessmentError,
    SeqOrderError,
    UnknownRiskError,
    risk_assessment_audit_event,
)

DIGEST = "sha256:" + "a" * 64

_STDLIB = {
    "hashlib",
    "math",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "canonical_json",
    "json",  # canonicalizer fallback
}


def test_version_schema_and_stdlib_only():
    assert RISK_ASSESSMENT_VERSION == "risk-assessment.v1"
    assert RISK_ASSESSMENT_SCHEMA == "northstar.risk-assessment.v1"
    src = Path(__file__).resolve().parents[1] / "risk_assessment.py"
    tree = ast.parse(src.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= _STDLIB, imports - _STDLIB


def test_identify_roundtrip_and_verify():
    ledger = RiskAssessment()
    rec = ledger.identify("security", 1, title_digest=DIGEST)
    assert rec.risk_id == "risk-1"
    assert rec.category == "security"
    assert rec.schema == RISK_ASSESSMENT_SCHEMA
    assert rec.verify()
    assert ledger.risk("risk-1", 2) is rec
    assert ledger.risk_ids(2) == ("risk-1",)


def test_identify_bad_inputs_burn_seq_and_book_rejected():
    ledger = RiskAssessment()
    bad = [None, 123, True, "", "x" * 300, "not-a-category", "SECURITY"]
    for i, cat in enumerate(bad, start=1):
        with pytest.raises(RiskAssessmentError):
            ledger.identify(cat, i)
    # every failed mutation consumed its seq and booked a rejected row
    assert ledger._seq == len(bad)
    kinds = [e["kind"] for e in ledger.audit_log()]
    assert kinds.count("risk-assessment.rejected") == len(bad)
    with pytest.raises(BadDigestError):
        ledger.identify("security", len(bad) + 1, title_digest="raw-text")


def test_score_roundtrip_and_exact_fraction_math():
    ledger = RiskAssessment()
    ledger.identify("safety", 1)
    scr = ledger.score("risk-1", 2, 0.5, 0.8)
    assert scr.score_id == "scr-1"
    assert scr.likelihood_text == "1/2"
    assert scr.impact_text == "4/5"
    assert scr.score_text == "2/5"  # exact, no floats
    assert scr.rating == "high"
    assert scr.verify()
    # zero boundary: exact reduction
    scr2 = ledger.score("risk-1", 3, 0, 1)
    assert scr2.score_text == "0/1" and scr2.rating == "low"
    assert scr2.verify()


def test_score_rating_boundaries():
    ledger = RiskAssessment()
    ledger.identify("operational", 1)
    cases = [
        (0.14, "low"),
        (0.15, "moderate"),  # inclusive lower edge
        (0.34, "moderate"),
        (0.35, "high"),
        (0.64, "high"),
        (0.65, "critical"),
        (1, "critical"),  # ints 0/1 accepted as float
    ]
    for i, (impact, rating) in enumerate(cases, start=2):
        scr = ledger.score("risk-1", i, 1, impact)
        assert scr.rating == rating, (impact, scr.rating)


def test_score_bad_inputs_burn_seq():
    ledger = RiskAssessment()
    ledger.identify("privacy", 1)
    before = ledger._seq
    for bad in (True, None, "x", 1.5, -0.1, float("nan"), float("inf"), 2):
        with pytest.raises(BadScoreError):
            ledger.score("risk-1", before + 1, bad, 0.5)
        before += 1
    for bad in (True, None, "x", float("nan"), -1):
        with pytest.raises(BadScoreError):
            ledger.score("risk-1", before + 1, 0.5, bad)
        before += 1
    assert ledger._seq == before
    with pytest.raises(UnknownRiskError):
        ledger.score("risk-99", before + 1, 0.5, 0.5)


def test_score_multiple_scores_latest_wins_in_report():
    ledger = RiskAssessment()
    ledger.identify("financial", 1)
    ledger.score("risk-1", 2, 0.1, 0.1)  # low
    ledger.score("risk-1", 3, 0.9, 0.9)  # critical
    assert len(ledger.scores_for("risk-1", 3)) == 2
    report = ledger.report(4)
    assert dict(report.by_rating) == {"critical": 1}
    assert report.verify()


def test_mitigate_roundtrip_and_escalation_chain():
    ledger = RiskAssessment()
    ledger.identify("compliance", 1)
    m1 = ledger.mitigate("risk-1", 2, "reduce", action_digest=DIGEST)
    assert m1.mitigation_id == "mit-1"
    assert m1.verify()
    # same risk can be mitigated again (escalation chain)
    m2 = ledger.mitigate("risk-1", 3, "accept")
    assert m2.mitigation_id == "mit-2"
    assert m2.verify()
    assert len(ledger.mitigations_for("risk-1", 3)) == 2
    assert ledger.is_mitigated("risk-1", 3)


def test_mitigate_bad_inputs():
    ledger = RiskAssessment()
    ledger.identify("technical", 1)
    for i, bad in enumerate(["nope", "", True, None], start=2):
        with pytest.raises(BadStrategyError):
            ledger.mitigate("risk-1", i, bad)
    with pytest.raises(UnknownRiskError):
        ledger.mitigate("risk-99", 6, "avoid")
    for good in ("avoid", "reduce", "transfer", "accept"):
        ledger.mitigate("risk-1", 7 + ("avoid", "reduce", "transfer", "accept").index(good), good)
    with pytest.raises(UnknownRiskError):
        ledger.is_mitigated("risk-99", 12)


def test_seq_discipline_rewind_bare_and_malformed():
    ledger = RiskAssessment()
    ledger.identify("reputational", 1)
    with pytest.raises(SeqOrderError):
        ledger.identify("reputational", 1)  # rewind raises bare
    assert ledger._seq == 1  # rewind consumed nothing
    assert "risk-assessment.rejected" not in [e["kind"] for e in ledger.audit_log()]
    for bad in (True, "x", 1.5, -1, None):
        with pytest.raises(SeqOrderError):
            ledger.identify("reputational", bad)


def test_views_are_pure_reads():
    ledger = RiskAssessment()
    ledger.identify("security", 1)
    ledger.score("risk-1", 2, 0.2, 0.2)
    n_events = len(ledger.audit_log())
    # same seq twice is fine for views; no seq consumption, no audit rows
    assert ledger.report(5).verify()
    assert ledger.report(5).verify()
    assert ledger._seq == 2
    assert len(ledger.audit_log()) == n_events
    assert ledger.risk("nope", 5) is None
    assert ledger.scores_for("risk-1", 5)[0].score_id == "scr-1"
    assert ledger.mitigations_for("risk-1", 5) == ()
    stats = ledger.stats(5)
    assert stats["risks"] == 1 and stats["scores"] == 1 and stats["open"] == 1


def test_report_counts_and_open_risks():
    ledger = RiskAssessment()
    ledger.identify("security", 1)
    ledger.identify("safety", 2)
    ledger.score("risk-1", 3, 0.5, 0.8)  # high
    ledger.mitigate("risk-1", 4, "avoid")
    report = ledger.report(5)
    assert report.verify()
    assert report.total_risks == 2
    assert dict(report.by_category) == {"safety": 1, "security": 1}
    assert dict(report.by_rating) == {"high": 1, "unscored": 1}
    assert report.mitigations_applied == 1
    assert dict(report.by_strategy) == {"avoid": 1}
    assert report.open_risks == ("risk-2",)


def test_audit_shapes_leak_ban_and_bad_kind():
    ledger = RiskAssessment()
    ledger.identify("privacy", 1, title_digest=DIGEST)
    evts = ledger.audit_log()
    assert evts[0]["schema"] == "audit.ndjson/1"
    assert evts[0]["module"] == "risk-assessment"
    assert evts[0]["kind"] == "risk-assessment.identified"
    for key in ("title", "description", "action", "text", "value", "reason"):
        with pytest.raises(Exception):
            risk_assessment_audit_event("risk-assessment.identified", 99, **{key: "x"})
    with pytest.raises(Exception):
        risk_assessment_audit_event("bogus.kind", 99)
    blob = repr(evts)
    assert "super secret" not in blob


def test_cross_instance_digest_determinism():
    a, b = RiskAssessment(), RiskAssessment()
    ra = a.identify("security", 1, title_digest=DIGEST)
    rb = b.identify("security", 1, title_digest=DIGEST)
    assert ra.digest == rb.digest
    sa = a.score("risk-1", 2, 0.5, 0.8)
    sb = b.score("risk-1", 2, 0.5, 0.8)
    assert sa.digest == sb.digest
    # tampering breaks verify
    object.__setattr__(sa, "rating", "low")
    assert not sa.verify()
    ra2 = a.identify("safety", 3)
    assert ra2.digest != ra.digest


def test_main_self_check_subprocess():
    out = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[1] / "risk_assessment.py")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert "risk-assessment OK: identify, score, mitigate, report, pins" in out.stdout
