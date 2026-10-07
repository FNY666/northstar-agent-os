"""Tests for ai_failure.py - AI-failure report/analysis decision ledger."""

import dataclasses
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "ai_failure.py"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


af = _load("ai_failure_test_mod")

DIGEST = "sha256:" + "ab" * 32


def _ledger():
    return af.AIFailure()


# 1 --------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert af.AI_FAILURE_VERSION == "ai-failure.v1"
    assert af.SCHEMA_PIN == "northstar.ai-failure.v1"
    assert af.stdlib_only() is True
    assert set(af.POSTURES) == {
        "unreported",
        "critical-open",
        "open",
        "inconclusive",
        "mitigated",
        "resolved",
    }
    assert set(af.RETIRE_REASONS) == {
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    }
    assert set(af.VERIFY_VERDICTS) == {"verified", "tampered"}
    assert af.CRITICAL_SEVERITY == 80
    assert len(af.FAILURE_KINDS) == 8
    assert len(af.ANALYSIS_KINDS) == 8
    assert len(af.OUTCOMES) == 5


# 2 --------------------------------------------------------------------------


def test_report_roundtrip_and_minting():
    ledger = _ledger()
    rec = ledger.report(
        "sys-1", 1, failure_kind="model-output-failure", severity=90,
        report_digest=DIGEST,
    )
    assert rec.report_id == "rpt-1"
    assert rec.system_id == "sys-1"
    assert rec.failure_kind == "model-output-failure"
    assert rec.severity == 90
    assert rec.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 1  # type: ignore
    rows = ledger.audit_log(2)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-failure"
    assert row["version"] == "ai-failure.v1"
    assert row["kind"] == "reported"
    assert row["seq"] == 1
    assert row["details"]["report_id"] == "rpt-1"
    assert "incident_log" not in row["details"]


# 3 --------------------------------------------------------------------------


def test_report_bad_inputs_seq_burn_and_rejected():
    ledger = _ledger()
    n = 0

    def burn():
        nonlocal n
        n += 1
        return n

    with pytest.raises(af.BadSystemError):
        ledger.report("", burn(), failure_kind="model-output-failure")
    with pytest.raises(af.BadSystemError):
        ledger.report(None, burn(), failure_kind="model-output-failure")
    with pytest.raises(af.BadFailureKindError):
        ledger.report("sys-1", burn(), failure_kind="bogus-kind")
    with pytest.raises(af.BadSeverityError):
        ledger.report("sys-1", burn(), severity=True)
    with pytest.raises(af.BadSeverityError):
        ledger.report("sys-1", burn(), severity=-1)
    with pytest.raises(af.BadSeverityError):
        ledger.report("sys-1", burn(), severity=101)
    with pytest.raises(af.BadSeverityError):
        ledger.report("sys-1", burn(), severity=1.5)
    with pytest.raises(af.BadDigestError):
        ledger.report("sys-1", burn(), report_digest="not-a-digest")
    with pytest.raises(af.BadDigestError):
        ledger.report("sys-1", burn(), report_digest="sha256:" + "zz" * 32)

    rows = ledger.audit_log(100)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 9
    kinds = {r["details"]["rejected_kind"] for r in rejected}
    assert "BadSystemError" in kinds
    assert "BadFailureKindError" in kinds
    assert "BadSeverityError" in kinds
    assert "BadDigestError" in kinds

    # rewind raises bare - no seq burn, no new row
    before = len(ledger.audit_log(101))
    with pytest.raises(af.SeqOrderError):
        ledger.report("sys-1", 1)
    assert len(ledger.audit_log(102)) == before
    # failed mutations consumed seq: next live call needs n+1
    rec = ledger.report("sys-1", 10, failure_kind="system-outage", severity=10)
    assert rec.report_id == "rpt-1"


# 4 --------------------------------------------------------------------------


def test_full_failure_kind_vocabulary():
    ledger = _ledger()
    for i, kind in enumerate(af.FAILURE_KINDS, start=1):
        rec = ledger.report("sys-1", i, failure_kind=kind, severity=i % 101)
        assert rec.report_id == f"rpt-{i}"
        assert rec.verify() is True
    assert ledger.report_ids(100) == [f"rpt-{i}" for i in range(1, 9)]


# 5 --------------------------------------------------------------------------


def test_analyze_roundtrip_and_minting():
    ledger = _ledger()
    rec = ledger.report("sys-1", 1, failure_kind="safety-violation", severity=50)
    anl = ledger.analyze(
        rec.report_id, 2, analysis_kind="postmortem", outcome="open",
        analysis_digest=DIGEST,
    )
    assert anl.analysis_id == "anl-1"
    assert anl.report_id == rec.report_id
    assert anl.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        anl.outcome = "resolved"  # type: ignore
    assert ledger.analyses_for(rec.report_id, 3) == ["anl-1"]
    rows = ledger.audit_log(4)
    assert rows[-1]["kind"] == "analyzed"
    assert rows[-1]["details"]["analysis_id"] == "anl-1"
    assert rows[-1]["details"]["outcome"] == "open"


# 6 --------------------------------------------------------------------------


def test_analyze_refusals():
    ledger = _ledger()
    rec = ledger.report("sys-1", 1, failure_kind="data-corruption", severity=20)
    n = 1

    def burn():
        nonlocal n
        n += 1
        return n

    with pytest.raises(af.UnknownReportError):
        ledger.analyze("rpt-999", burn())
    with pytest.raises(af.UnknownReportError):
        ledger.analyze("", burn())
    with pytest.raises(af.BadAnalysisKindError):
        ledger.analyze(rec.report_id, burn(), analysis_kind="bogus")
    with pytest.raises(af.BadOutcomeError):
        ledger.analyze(rec.report_id, burn(), outcome="bogus")
    with pytest.raises(af.BadDigestError):
        ledger.analyze(rec.report_id, burn(), analysis_digest="bad")
    rows = ledger.audit_log(100)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 5
    # retired system: fail-closed
    ledger.retire("sys-1", 7)
    with pytest.raises(af.RetiredSystemError):
        ledger.analyze(rec.report_id, 8)
    rows = ledger.audit_log(101)
    assert len([r for r in rows if r["kind"] == "rejected"]) == 6


# 7 --------------------------------------------------------------------------


def test_full_analysis_kind_outcome_vocabulary():
    ledger = _ledger()
    rec = ledger.report("sys-1", 1, failure_kind="performance-degradation")
    seq = 1
    expected = []
    for kind in af.ANALYSIS_KINDS:
        for outcome in af.OUTCOMES:
            seq += 1
            anl = ledger.analyze(
                rec.report_id, seq, analysis_kind=kind, outcome=outcome
            )
            assert anl.verify() is True
            expected.append(anl.analysis_id)
    assert len(expected) == 40
    assert ledger.analyses_for(rec.report_id, seq + 1) == expected


# 8 --------------------------------------------------------------------------


def test_verify_read_purity_and_tamper():
    ledger = _ledger()
    rec = ledger.report("sys-1", 1, failure_kind="bias-incident", severity=10)
    anl = ledger.analyze(rec.report_id, 2, outcome="mitigated")
    # same-seq twice: pure read, no audit rows, no seq consumption
    before = len(ledger.audit_log(3))
    v1 = ledger.verify(rec.report_id, 4)
    v2 = ledger.verify(rec.report_id, 4)
    va = ledger.verify(anl.analysis_id, 4)
    assert v1.verdict == "verified" and v1.integrity_ok is True
    assert v2.verdict == "verified"
    assert va.verdict == "verified"
    assert v1.verify() is True
    assert len(ledger.audit_log(5)) == before
    with pytest.raises(af.UnknownRecordError):
        ledger.verify("rpt-999", 6)
    with pytest.raises(af.SeqOrderError):
        ledger.verify(rec.report_id, -1)
    # tamper reported as data, never raised
    object.__setattr__(rec, "severity", 99)
    tampered = ledger.verify(rec.report_id, 7)
    assert tampered.verdict == "tampered"
    assert tampered.integrity_ok is False
    assert tampered.verify() is True


# 9 --------------------------------------------------------------------------


def test_evaluate_posture_math():
    # unreported
    ledger = _ledger()
    ev = ledger.evaluate("no-such-system", 1)
    assert ev.posture == "unreported"
    assert ev.n_reports == 0
    assert ev.verify() is True

    # critical-open: unanalyzed severity >= 80
    ledger = _ledger()
    ledger.report("sys-1", 1, failure_kind="security-breach", severity=80)
    assert ledger.evaluate("sys-1", 2).posture == "critical-open"

    # open: unanalyzed low severity
    ledger = _ledger()
    ledger.report("sys-1", 1, failure_kind="deployment-incident", severity=10)
    ev = ledger.evaluate("sys-1", 2)
    assert ev.posture == "open"
    assert ev.n_reports == 1 and ev.n_analyzed == 0 and ev.n_open == 1

    # critical-outranks-nothing-else but unanalyzed
    ledger = _ledger()
    ledger.report("sys-1", 1, failure_kind="safety-violation", severity=100)
    ledger.report("sys-1", 2, failure_kind="bias-incident", severity=5)
    ev = ledger.evaluate("sys-1", 3)
    assert ev.posture == "critical-open"
    assert ev.n_critical == 1

    # inconclusive analysis outcome
    ledger = _ledger()
    rec = ledger.report("sys-1", 1, failure_kind="model-output-failure", severity=10)
    ledger.analyze(rec.report_id, 2, outcome="inconclusive")
    ev = ledger.evaluate("sys-1", 3)
    assert ev.posture == "inconclusive"
    assert ev.n_analyzed == 1

    # wont-fix keeps posture open
    ledger = _ledger()
    rec = ledger.report("sys-1", 1, failure_kind="data-corruption", severity=10)
    ledger.analyze(rec.report_id, 2, outcome="wont-fix")
    assert ledger.evaluate("sys-1", 3).posture == "open"

    # mitigated: all analyzed, latest mitigated, none open/wont-fix
    ledger = _ledger()
    r1 = ledger.report("sys-1", 1, failure_kind="system-outage", severity=30)
    r2 = ledger.report("sys-1", 2, failure_kind="bias-incident", severity=20)
    ledger.analyze(r1.report_id, 3, outcome="mitigated")
    ledger.analyze(r2.report_id, 4, outcome="resolved")
    ev = ledger.evaluate("sys-1", 5)
    assert ev.posture == "mitigated"
    assert ev.n_reports == 2 and ev.n_analyzed == 2 and ev.n_open == 0

    # resolved: every report resolved
    ledger = _ledger()
    r1 = ledger.report("sys-1", 1, failure_kind="performance-degradation", severity=5)
    ledger.analyze(r1.report_id, 2, outcome="open")
    ledger.analyze(r1.report_id, 3, outcome="resolved")
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "resolved"
    assert ev.integrity_ok is True

    # unknown system id still validates id shape
    ledger = _ledger()
    with pytest.raises(af.BadSystemError):
        ledger.evaluate("", 1)


# 10 -------------------------------------------------------------------------


def test_evaluate_read_purity_and_integrity_flip():
    ledger = _ledger()
    rec = ledger.report("sys-1", 1, failure_kind="deployment-incident", severity=10)
    ledger.analyze(rec.report_id, 2, outcome="resolved")
    before = len(ledger.audit_log(3))
    e1 = ledger.evaluate("sys-1", 4)
    e2 = ledger.evaluate("sys-1", 4)
    assert e1.posture == "resolved"
    assert e1.integrity_ok is True
    assert e1.verify() is True
    assert len(ledger.audit_log(5)) == before
    object.__setattr__(rec, "severity", 42)
    e3 = ledger.evaluate("sys-1", 6)
    assert e3.integrity_ok is False  # tamper flips as data
    assert e3.verify() is True


# 11 -------------------------------------------------------------------------


def test_retire_terminality():
    ledger = _ledger()
    rec = ledger.report("sys-1", 1, failure_kind="safety-violation", severity=10)
    with pytest.raises(af.UnknownSystemError):
        ledger.retire("ghost", 2)
    with pytest.raises(af.BadReasonError):
        ledger.retire("sys-1", 3, reason="bogus")
    ret = ledger.retire("sys-1", 4)
    assert ret.verify() is True
    with pytest.raises(af.RetiredSystemError):
        ledger.retire("sys-1", 5)
    # ids never recycled
    assert ledger.retired_ids(6) == ["sys-1"]
    # post-retire mutations refused
    with pytest.raises(af.RetiredSystemError):
        ledger.report("sys-1", 7, failure_kind="system-outage")
    with pytest.raises(af.RetiredSystemError):
        ledger.analyze(rec.report_id, 8)
    # post-retire reads still work
    assert ledger.failure_record(rec.report_id, 9).report_id == rec.report_id
    assert ledger.evaluate("sys-1", 10).n_reports == 1
    assert ledger.verify(rec.report_id, 11).verdict == "verified"


# 12 -------------------------------------------------------------------------


def test_seq_discipline():
    ledger = _ledger()
    # genesis rewind raises bare with zero rows
    with pytest.raises(af.SeqOrderError):
        ledger.report("sys-1", 0)
    assert ledger.audit_log(1) == []
    # malformed seqs raise bare, burn nothing
    for bad in (True, False, 1.5, "1", None, [1]):
        with pytest.raises(af.SeqOrderError):
            ledger.report("sys-1", bad)
    assert ledger.audit_log(2) == []
    # failed mutation consumes seq
    with pytest.raises(af.BadFailureKindError):
        ledger.report("sys-1", 1, failure_kind="bogus")
    with pytest.raises(af.SeqOrderError):
        ledger.report("sys-1", 1)
    rec = ledger.report("sys-1", 2, failure_kind="system-outage")
    assert rec.report_id == "rpt-1"
    # rewind after live rows still raises bare
    before = len(ledger.audit_log(3))
    with pytest.raises(af.SeqOrderError):
        ledger.report("sys-1", 2)
    assert len(ledger.audit_log(4)) == before


# 13 -------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    # unknown audit kind
    with pytest.raises(af.AuditKindError):
        af.ai_failure_audit_event("bogus", 1)
    # bad audit seq
    with pytest.raises(af.SeqOrderError):
        af.ai_failure_audit_event("reported", True)
    # banned raw keys blocked at the builder
    for key in ("incident_log", "stack_trace", "user_data", "pii", "notes"):
        with pytest.raises(af.AIFailureError):
            af.ai_failure_audit_event("reported", 1, **{key: "raw"})
    # pinned vocab values and digest pins pass through
    row = af.ai_failure_audit_event(
        "analyzed", 2, failure_kind="safety-violation",
        report_digest=DIGEST, outcome="open",
    )
    assert row["kind"] == "analyzed"
    assert row["details"]["report_digest"] == DIGEST
    # ledger-level rejected rows carry the detail
    ledger = _ledger()
    with pytest.raises(af.BadFailureKindError):
        ledger.report("sys-1", 1, failure_kind="bogus")
    rows = ledger.audit_log(2)
    assert rows[0]["kind"] == "rejected"
    assert rows[0]["details"]["rejected_kind"] == "BadFailureKindError"


# 14 -------------------------------------------------------------------------


def test_views_and_stats():
    ledger = _ledger()
    r1 = ledger.report("sys-1", 1, failure_kind="model-output-failure", severity=5)
    r2 = ledger.report("sys-2", 2, failure_kind="deployment-incident", severity=6)
    a1 = ledger.analyze(r1.report_id, 3, outcome="open")
    assert ledger.report_ids(4) == ["rpt-1", "rpt-2"]
    assert ledger.analysis_ids(5) == ["anl-1"]
    assert ledger.system_ids(6) == ["sys-1", "sys-2"]
    assert ledger.reports_for("sys-1", 7) == ["rpt-1"]
    assert ledger.reports_for("ghost", 8) == []
    assert ledger.analyses_for(r1.report_id, 9) == ["anl-1"]
    assert ledger.analyses_for("rpt-999", 10) == []
    assert ledger.analysis_record(a1.analysis_id, 11).analysis_id == "anl-1"
    assert ledger.retired_ids(12) == []
    stats = ledger.stats(13)
    assert stats == {
        "n_reports": 2,
        "n_analyses": 1,
        "n_systems": 2,
        "n_retired": 0,
        "seq": 3,
    }
    with pytest.raises(af.UnknownReportError):
        ledger.failure_record("rpt-999", 14)
    with pytest.raises(af.UnknownAnalysisError):
        ledger.analysis_record("anl-999", 15)
    with pytest.raises(af.SeqOrderError):
        ledger.report_ids(-1)


# 15 -------------------------------------------------------------------------


def test_cross_instance_determinism_thread_reads_and_main():
    def build():
        ledger = af.AIFailure()
        rec = ledger.report(
            "sys-1", 1, failure_kind="safety-violation", severity=70,
            report_digest=DIGEST,
        )
        anl = ledger.analyze(
            rec.report_id, 2, analysis_kind="postmortem",
            outcome="mitigated", analysis_digest=DIGEST,
        )
        return ledger, rec, anl

    l1, r1, a1 = build()
    l2, r2, a2 = build()
    assert r1.digest == r2.digest
    assert a1.digest == a2.digest
    assert r1.report_id == r2.report_id and a1.analysis_id == a2.analysis_id
    # 8-thread read smoke
    errors = []

    def reader():
        try:
            for _ in range(50):
                assert l1.evaluate("sys-1", 1).posture == "mitigated"
                assert l1.verify(r1.report_id, 2).verdict == "verified"
                assert l1.stats(3)["n_reports"] == 1
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    # main() self-check in a subprocess
    result = subprocess.run(
        [sys.executable, str(MOD_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "ai-failure OK: report, analyze, verify, evaluate, retire, pins, audit" in (
        result.stdout
    )
