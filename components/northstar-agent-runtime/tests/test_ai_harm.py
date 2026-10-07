"""Tests for the ai_harm decision ledger (15 tests, as spec'd)."""

import ast
import dataclasses
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, "..")

import ai_harm
from ai_harm import (
    AIHarm,
    AI_HARM_VERSION,
    SCHEMA_PIN,
    HARM_KINDS,
    ASSESS_VERDICTS,
    MITIGATION_STRATEGIES,
    POSTURES,
    RETIRE_REASONS,
    AUDIT_KINDS,
    ai_harm_audit_event,
    AssessmentRecord,
    MitigationRecord,
    RetireRecord,
    EvaluationReport,
    VerificationReport,
    AIHarmError,
    BadSystemError,
    UnknownSystemError,
    RetiredSystemError,
    BadHarmKindError,
    BadVerdictError,
    BadSeverityError,
    BadDigestError,
    BadReasonError,
    UnknownAssessmentError,
    UnknownMitigationError,
    UnknownRecordError,
    BadStrategyError,
    SeqOrderError,
    AuditKindError,
    stdlib_only,
)


def sha256_pin():
    return "sha256:" + "ab" * 32


def fresh():
    return AIHarm()


# 1. version/schema/vocabulary pins ------------------------------------------


def test_pins():
    assert AI_HARM_VERSION == "ai-harm.v1"
    assert SCHEMA_PIN == "northstar.ai-harm.v1"
    assert len(HARM_KINDS) == 8
    assert len(ASSESS_VERDICTS) == 5
    assert len(MITIGATION_STRATEGIES) == 8
    assert len(POSTURES) == 5
    assert len(RETIRE_REASONS) == 4
    assert len(AUDIT_KINDS) == 4


# 2. stdlib-only AST check -----------------------------------------------------


def test_stdlib_only():
    import pathlib

    src = pathlib.Path(ai_harm.__file__).read_text()
    tree = ast.parse(src)
    allowed = {
        "__future__",
        "ast",
        "canonical_json",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed
    assert stdlib_only() is True


# 3. assess roundtrip / verify() / frozen-ness --------------------------------


def test_assess_roundtrip_verify_frozen():
    ledger = fresh()
    rec = ledger.assess("sys-1", 1, "physical-harm", "harm-detected", 40, sha256_pin())
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.harm_kind == "physical-harm"
    assert rec.verdict == "harm-detected"
    assert rec.severity == 40
    assert rec.assessment_digest == sha256_pin()
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    assert isinstance(rec, AssessmentRecord)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "no-harm"  # type: ignore[misc]


# 4. assess bad-input table + seq-burn + rejected-row accounting ---------------


def test_assess_bad_inputs_burn_seq():
    ledger = fresh()
    n_rejected = 0
    bad = [
        ("", 1, "physical-harm", "harm-detected", 40),
        ("sys-1", 1, "bogus-kind", "harm-detected", 40),
        ("sys-1", 1, "physical-harm", "bogus", 40),
        ("sys-1", 1, "physical-harm", "harm-detected", -1),
        ("sys-1", 1, "physical-harm", "harm-detected", 101),
        ("sys-1", 1, "physical-harm", "harm-detected", True),
        ("sys-1", 1, "physical-harm", "harm-detected", 40.5),
    ]
    seq = 1
    for system_id, _, harm_kind, verdict, severity in bad:
        with pytest.raises(AIHarmError):
            ledger.assess(system_id, seq, harm_kind, verdict, severity)
        n_rejected += 1
        rows = [r for r in ledger.audit_log(seq) if r["kind"] == "rejected"]
        assert len(rows) == n_rejected
        seq += 1
    # bad digest is also refused and burns the seq
    with pytest.raises(BadDigestError):
        ledger.assess("sys-1", seq, "physical-harm", "harm-detected", 40, "nope")
    rows = [r for r in ledger.audit_log(seq) if r["kind"] == "rejected"]
    assert len(rows) == n_rejected + 1
    # rewind raises bare with no new rows
    before = len(ledger.audit_log(seq + 1))
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-1", 1, "physical-harm", "harm-detected", 0)
    assert len(ledger.audit_log(seq + 1)) == before


# 5. full 8-harm-kind vocabulary ----------------------------------------------


def test_full_harm_kind_vocabulary():
    ledger = fresh()
    seq = 1
    for kind in HARM_KINDS:
        rec = ledger.assess("sys-kinds", seq, kind, "not-assessed", 0)
        assert rec.harm_kind == kind
        assert rec.verify()
        seq += 1


# 6. full 5-verdict vocabulary -------------------------------------------------


def test_full_verdict_vocabulary():
    ledger = fresh()
    seq = 1
    for verdict in ASSESS_VERDICTS:
        rec = ledger.assess("sys-verdicts", seq, "economic-harm", verdict, 0)
        assert rec.verdict == verdict
        assert rec.verify()
        seq += 1


# 7. mitigate roundtrip / minted ids / unknown-assessment refusal ---------------


def test_mitigate_roundtrip_and_refusals():
    ledger = fresh()
    rec = ledger.assess("sys-2", 1, "social-harm", "harm-detected", 70)
    mit = ledger.mitigate(rec.assessment_id, 2, "remediation", sha256_pin())
    assert mit.mitigation_id == "mit-1"
    assert mit.assessment_id == rec.assessment_id
    assert mit.system_id == "sys-2"
    assert mit.strategy == "remediation"
    assert mit.verify() is True
    assert isinstance(mit, MitigationRecord)
    with pytest.raises(dataclasses.FrozenInstanceError):
        mit.strategy = "no-action"  # type: ignore[misc]
    # unknown assessment refused and burns seq
    with pytest.raises(UnknownAssessmentError):
        ledger.mitigate("asm-999", 3, "containment")
    assert ledger.stats(4)["n_mitigations"] == 1
    # bad strategy refused
    with pytest.raises(BadStrategyError):
        ledger.mitigate(rec.assessment_id, 4, "bogus")
    assert ledger.stats(5)["n_mitigations"] == 1


# 8. full 8-strategy vocabulary + chainable -------------------------------------


def test_full_strategy_vocabulary_chain():
    ledger = fresh()
    rec = ledger.assess("sys-3", 1, "rights-violation", "harm-detected", 90)
    seq = 2
    for strategy in MITIGATION_STRATEGIES:
        mit = ledger.mitigate(rec.assessment_id, seq, strategy)
        assert mit.strategy == strategy
        assert mit.verify()
        seq += 1
    assert len(ledger.mitigations_for(rec.assessment_id, seq)) == 8


# 9. evaluate posture math (all 5 postures + precedence) ------------------------


def test_evaluate_posture_math():
    ledger = fresh()
    # unassessed: only not-assessed verdicts booked
    ledger.assess("sys-a", 1, "physical-harm", "not-assessed", 0)
    evl = ledger.evaluate("sys-a", 2)
    assert evl.posture == "unassessed"
    assert evl.n_assessments == 1
    assert evl.n_not_assessed == 1
    # harm-open: unmitigated harm-detected outranks everything
    rec = ledger.assess("sys-b", 3, "economic-harm", "harm-detected", 80)
    ledger.assess("sys-b", 4, "economic-harm", "no-harm", 0)
    evl = ledger.evaluate("sys-b", 5)
    assert evl.posture == "harm-open"
    assert evl.n_harm_detected == 1
    assert evl.n_mitigated == 0
    # mitigated once the harm is covered
    ledger.mitigate(rec.assessment_id, 6, "remediation")
    evl = ledger.evaluate("sys-b", 7)
    assert evl.posture == "mitigated"
    assert evl.n_mitigated == 1
    # contested: suspected outranks mitigated/no-harm
    ledger.assess("sys-c", 8, "psychological-harm", "no-harm", 0)
    ledger.assess("sys-c", 9, "psychological-harm", "suspected", 30)
    evl = ledger.evaluate("sys-c", 10)
    assert evl.posture == "contested"
    assert evl.n_suspected == 1
    # no-harm: all verdicts clean
    ledger.assess("sys-d", 11, "environmental-harm", "no-harm", 0)
    ledger.assess("sys-d", 12, "environmental-harm", "no-harm", 0)
    evl = ledger.evaluate("sys-d", 13)
    assert evl.posture == "no-harm"
    assert evl.n_no_harm == 2
    assert evl.integrity_ok is True
    # unknown system raises fail-closed
    with pytest.raises(UnknownSystemError):
        ledger.evaluate("sys-ghost", 14)


# 10. verify() semantics + tamper-as-data + read purity -------------------------


def test_verify_semantics_and_read_purity():
    ledger = fresh()
    rec = ledger.assess("sys-4", 1, "informational-harm", "harm-detected", 55)
    mit = ledger.mitigate(rec.assessment_id, 2, "containment")
    before = len(ledger.audit_log(3))
    rep = ledger.verify(rec.assessment_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    assert isinstance(rep, VerificationReport)
    # same-seq twice: no audit rows, no seq consumption
    rep2 = ledger.verify(rec.assessment_id, 3)
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(3)) == before
    assert ledger.stats(3)["seq"] == 2
    # verify works for mitigation ids too
    rep3 = ledger.verify(mit.mitigation_id, 4)
    assert rep3.verdict == "verified"
    # tamper is reported as data, never raised
    object.__setattr__(rec, "severity", 0)
    assert rec.verify() is False
    rep4 = ledger.verify(rec.assessment_id, 5)
    assert rep4.verdict == "tampered"
    assert rep4.integrity_ok is False
    evl = ledger.evaluate("sys-4", 6)
    assert evl.integrity_ok is False
    # unknown record raises fail-closed
    with pytest.raises(UnknownRecordError):
        ledger.verify("asm-999", 7)


# 11. retire terminality + id non-recycling + post-retire reads ------------------


def test_retire_terminality():
    ledger = fresh()
    rec = ledger.assess("sys-5", 1, "physical-harm", "no-harm", 0)
    ret = ledger.retire("sys-5", 2)
    assert isinstance(ret, RetireRecord)
    assert ret.reason == "manual"
    assert ret.verify() is True
    assert ledger.retired_ids(3) == ("sys-5",)
    # post-retire mutations refused (seq burns), reads still work
    with pytest.raises(RetiredSystemError):
        ledger.assess("sys-5", 3, "physical-harm", "no-harm", 0)
    with pytest.raises(RetiredSystemError):
        ledger.mitigate(rec.assessment_id, 4, "remediation")
    recs = ledger.assessments_for("sys-5", 5)
    assert len(recs) == 1
    evl = ledger.evaluate("sys-5", 5)
    assert evl.posture == "no-harm"
    # double-retire refused (fail-closed; retired check fires first)
    with pytest.raises(RetiredSystemError):
        ledger.retire("sys-5", 5)
    # bad reason refused and burns its seq
    ledger2 = fresh()
    ledger2.assess("sys-6", 1, "social-harm", "no-harm", 0)
    with pytest.raises(BadReasonError):
        ledger2.retire("sys-6", 2, "bogus")
    assert ledger2.stats(3)["seq"] == 2
    rows = [r for r in ledger2.audit_log(3) if r["kind"] == "rejected"]
    assert len(rows) == 1
    # unknown system refused
    with pytest.raises(UnknownSystemError):
        ledger2.retire("sys-ghost", 3)
    # all four reasons accepted
    seq = 4
    for reason in RETIRE_REASONS:
        name = f"sys-r-{reason}"
        ledger2.assess(name, seq, "social-harm", "no-harm", 0)
        ret = ledger2.retire(name, seq + 1, reason)
        assert ret.reason == reason
        seq += 2


# 12. seq discipline ------------------------------------------------------------


def test_seq_discipline():
    ledger = fresh()
    # genesis rewind (seq 0) raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-6", 0, "physical-harm", "no-harm", 0)
    assert ledger.audit_log(1) == ()
    ledger.assess("sys-6", 1, "physical-harm", "no-harm", 0)
    # rewind raises bare with zero new rows
    before = len(ledger.audit_log(2))
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-6", 1, "physical-harm", "no-harm", 0)
    assert len(ledger.audit_log(2)) == before
    # malformed seqs raise bare (never burn)
    for bad in (True, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            ledger.assess("sys-6", bad, "physical-harm", "no-harm", 0)
    assert len(ledger.audit_log(2)) == before
    # failed mutation consumes seq
    with pytest.raises(BadHarmKindError):
        ledger.assess("sys-6", 2, "bogus", "no-harm", 0)
    assert ledger.stats(3)["seq"] == 2
    rows = [r for r in ledger.audit_log(3) if r["kind"] == "rejected"]
    assert len(rows) == 1
    assert rows[0]["details"]["rejected_kind"] == "BadHarmKindError"


# 13. audit shapes + leak ban + bad-kind -------------------------------------------


def test_audit_shapes_and_leak_ban():
    row = ai_harm_audit_event("assessed", 1, system_id="s", harm_kind="physical-harm")
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-harm"
    assert row["version"] == AI_HARM_VERSION
    assert row["kind"] == "assessed"
    assert row["seq"] == 1
    assert row["details"]["harm_kind"] == "physical-harm"
    # every banned key is refused at the builder level
    for key in (
        "incident_report",
        "harm_narrative",
        "victim_identity",
        "damages",
        "lawsuit",
        "payout",
        "complaint_text",
    ):
        with pytest.raises(AIHarmError):
            ai_harm_audit_event("assessed", 1, **{key: "raw"})
    # bad kind refused
    with pytest.raises(AuditKindError):
        ai_harm_audit_event("bogus", 1)
    # ledger-level: banned keys never cross the boundary either
    with pytest.raises(AIHarmError):
        ai_harm_audit_event("rejected", 1, incident="x")
    ledger = fresh()
    rec = ledger.assess("sys-7", 1, "discrimination-harm", "harm-detected", 60)
    rows = ledger.audit_log(2)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["assessed"]
    banned = {"incident", "victim", "damages", "lawsuit"}
    for r in rows:
        assert not (set(r["details"]) & banned)


# 14. cross-instance digest determinism + views/stats -------------------------------


def test_determinism_and_views():
    ledgers = [fresh(), fresh()]
    for ledger in ledgers:
        rec = ledger.assess("sys-8", 1, "economic-harm", "harm-detected", 25)
        ledger.mitigate(rec.assessment_id, 2, "compensation")
    a = ledgers[0].assessment_record("asm-1", 3)
    b = ledgers[1].assessment_record("asm-1", 3)
    assert a.digest == b.digest
    assert a.verify() and b.verify()
    assert ledgers[0].system_ids(3) == ("sys-8",)
    assert ledgers[0].assessment_ids(3) == ("asm-1",)
    assert ledgers[0].mitigation_ids(3) == ("mit-1",)
    assert len(ledgers[0].assessments_for("sys-8", 3)) == 1
    assert len(ledgers[0].mitigations_for("asm-1", 3)) == 1
    with pytest.raises(UnknownAssessmentError):
        ledgers[0].assessment_record("asm-999", 3)
    with pytest.raises(UnknownMitigationError):
        ledgers[0].mitigation_record("mit-999", 3)
    assert ledgers[0].assessments_for("sys-ghost", 3) == ()
    with pytest.raises(UnknownSystemError):
        ledgers[0].evaluate("sys-ghost", 3)
    stats = ledgers[0].stats(3)
    assert stats["n_systems"] == 1
    assert stats["n_assessments"] == 1
    assert stats["n_mitigations"] == 1
    assert stats["seq"] == 2
    evl = ledgers[0].evaluate("sys-8", 3)
    assert isinstance(evl, EvaluationReport)
    assert evl.verify() is True


# 15. 8-thread read smoke + main() subprocess check ---------------------------------


def test_threaded_reads_and_main():
    ledger = fresh()
    rec = ledger.assess("sys-9", 1, "social-harm", "harm-detected", 10)
    ledger.mitigate(rec.assessment_id, 2, "monitoring-escalation")
    errors = []

    def reader():
        try:
            for _ in range(50):
                evl = ledger.evaluate("sys-9", 3)
                assert evl.posture == "mitigated"
                rep = ledger.verify(rec.assessment_id, 3)
                assert rep.verdict == "verified"
                assert ledger.stats(3)["n_assessments"] == 1
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    proc = subprocess.run(
        [sys.executable, ai_harm.__file__],
        capture_output=True,
        text=True,
        cwd="..",
        timeout=60,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == (
        "ai-harm OK: assess, mitigate, verify, evaluate, retire, pins, audit"
    )
