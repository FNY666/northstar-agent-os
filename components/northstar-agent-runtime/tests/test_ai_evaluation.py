"""Tests for the AI-evaluation decision ledger, Simulated."""

import ast
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_evaluation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_evaluation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_evaluation"] = module
    spec.loader.exec_module(module)
    return module


ae = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ae.AI_EVALUATION_VERSION == "ai-evaluation.v1"
    assert ae.SCHEMA_PIN == "northstar.ai-evaluation.v1"
    assert ae.ASSESSMENT_KINDS == (
        "capability-eval",
        "safety-eval",
        "alignment-eval",
        "robustness-eval",
        "fairness-eval",
        "security-eval",
        "governance-eval",
        "field-eval",
    )
    assert ae.FINDINGS == (
        "pass",
        "marginal",
        "fail",
        "inconclusive",
        "not-assessed",
    )
    assert ae.EVAL_OUTCOMES == (
        "accepted",
        "rejected",
        "inconclusive",
        "superseded",
    )
    assert ae.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert set(ae.AUDIT_KINDS) == {
        "assessed",
        "evaluated",
        "retired",
        "rejected",
    }


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


# 3. assess roundtrip + verify()
def test_assess_roundtrip_and_verify():
    g = ae.AIEvaluation()
    rec = g.assess(
        "sys-a",
        1,
        assessment_kind="capability-eval",
        finding="pass",
        severity=42,
        assessment_digest=PIN,
    )
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-a"
    assert rec.assessment_kind == "capability-eval"
    assert rec.finding == "pass"
    assert rec.severity == 42
    assert rec.assessment_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.ai-evaluation.v1"
    # frozen
    with pytest.raises(FrozenInstanceError):
        rec.finding = "fail"  # type: ignore
    fetched = g.assessment_record("asm-1", 2)
    assert fetched == rec
    assert g.system_ids(3) == ("sys-a",)
    assert g.assessment_ids(4) == ("asm-1",)
    assert g.assessments_for("sys-a", 5) == ("asm-1",)


# 4. assess bad-input table + seq-burn + rejected rows
def test_assess_bad_inputs_and_seq_burn():
    g = ae.AIEvaluation()
    bad = [
        ("", "safety-eval", "pass", 0, PIN),  # empty id
        ("x" * 129, "safety-eval", "pass", 0, PIN),  # id too long
        (None, "safety-eval", "pass", 0, PIN),  # non-str id
        ("ok-1", "not-a-kind", "pass", 0, PIN),  # bad kind
        ("ok-1", "safety-eval", "not-a-finding", 0, PIN),  # bad finding
        ("ok-1", "safety-eval", "pass", -1, PIN),  # severity low
        ("ok-1", "safety-eval", "pass", 101, PIN),  # severity high
        ("ok-1", "safety-eval", "pass", True, PIN),  # bool severity
        ("ok-1", "safety-eval", "pass", "0", PIN),  # str severity
        ("ok-1", "safety-eval", "pass", 0, "nope"),  # bad digest
        ("ok-1", "safety-eval", "pass", 0, "sha256:" + "zz" * 32),  # bad hex
    ]
    seq = 1
    for sid, kind, finding, sev, digest in bad:
        with pytest.raises(ae.AIEvaluationError):
            g.assess(sid, seq, assessment_kind=kind, finding=finding,
                     severity=sev, assessment_digest=digest)
        seq += 1
    # each failed mutation burned its seq: reusing the last one rewinds bare
    with pytest.raises(ae.SeqOrderError):
        g.assess("ok-1", seq - 1, assessment_digest=PIN)
    assert g.stats(999)["rejected"] == len(bad)
    assert g.stats(999)["assessments"] == 0
    rows = g.audit_log(999)
    assert len(rows) == len(bad)
    assert all(r["kind"] == "rejected" for r in rows)
    assert all(r["details"]["method"] == "assess" for r in rows)


# 5. full 8-kind assessment vocabulary
def test_full_assessment_kind_vocabulary():
    g = ae.AIEvaluation()
    for i, kind in enumerate(ae.ASSESSMENT_KINDS):
        rec = g.assess(f"sys-{i}", i + 1, assessment_kind=kind,
                       finding="pass", assessment_digest=PIN)
        assert rec.assessment_kind == kind
    assert g.stats(999)["assessments"] == 8


# 6. full 5-finding vocabulary + severity bounds
def test_full_finding_vocabulary_and_severity_bounds():
    g = ae.AIEvaluation()
    for i, finding in enumerate(ae.FINDINGS):
        rec = g.assess(f"sys-{i}", i + 1, finding=finding,
                       assessment_digest=PIN)
        assert rec.finding == finding
    rec0 = g.assess("lo", 10, severity=0, assessment_digest=PIN)
    rec100 = g.assess("hi", 11, severity=100, assessment_digest=PIN)
    assert rec0.severity == 0
    assert rec100.severity == 100


# 7. evaluate roundtrip + minting + audit row
def test_evaluate_roundtrip_and_minting():
    g = ae.AIEvaluation()
    asm = g.assess("sys-a", 1, finding="pass", assessment_digest=PIN)
    evl = g.evaluate("asm-1", 2, outcome="accepted", evaluation_digest=PIN2)
    assert evl.evaluation_id == "evl-1"
    assert evl.assessment_id == "asm-1"
    assert evl.system_id == "sys-a"
    assert evl.outcome == "accepted"
    assert evl.evaluation_digest == PIN2
    assert evl.verify()
    assert evl.as_dict()["schema"] == "northstar.ai-evaluation.v1"
    with pytest.raises(FrozenInstanceError):
        evl.outcome = "rejected"  # type: ignore
    fetched = g.evaluation_record("evl-1", 3)
    assert fetched == evl
    assert g.evaluation_for("asm-1", 4) == "evl-1"
    assert g.evaluation_ids(5) == ("evl-1",)
    assert g.evaluations_for("sys-a", 6) == ("evl-1",)
    rows = g.audit_log(7)
    assert rows[-1]["kind"] == "evaluated"
    assert rows[-1]["details"]["outcome"] == "accepted"


# 8. evaluate refusal table + seq-burn
def test_evaluate_refusals_and_seq_burn():
    g = ae.AIEvaluation()
    g.assess("sys-a", 1, assessment_digest=PIN)
    g.evaluate("asm-1", 2, outcome="accepted", evaluation_digest=PIN)
    bad = [
        ("asm-999", "accepted", PIN),   # unknown assessment
        ("", "accepted", PIN),          # bad id
        ("asm-1", "not-an-outcome", PIN),  # bad outcome
        ("asm-1", "accepted", "badpin"),    # bad digest
        ("asm-1", "accepted", PIN),      # double evaluation
    ]
    seq = 3
    for aid, outcome, digest in bad:
        with pytest.raises(ae.AIEvaluationError):
            g.evaluate(aid, seq, outcome=outcome, evaluation_digest=digest)
        seq += 1
    # retire, then evaluation against a retired system's assessment refuses
    g.assess("sys-b", seq, assessment_digest=PIN)
    seq += 1
    g.retire("sys-b", seq)
    seq += 1
    with pytest.raises(ae.RetiredSystemError):
        g.evaluate("asm-2", seq, evaluation_digest=PIN)
    stats = g.stats(999)
    assert stats["rejected"] == len(bad) + 1
    assert stats["evaluations"] == 1


# 9. full 4-outcome vocabulary
def test_full_outcome_vocabulary():
    g = ae.AIEvaluation()
    for i, outcome in enumerate(ae.EVAL_OUTCOMES):
        g.assess(f"sys-{i}", i * 2 + 1, assessment_digest=PIN)
        evl = g.evaluate(f"asm-{i + 1}", i * 2 + 2, outcome=outcome,
                         evaluation_digest=PIN)
        assert evl.outcome == outcome
    assert g.stats(999)["evaluations"] == 4


# 10. verify semantics: verified/tamper-as-data/read purity/unknown refusal
def test_verify_semantics_and_read_purity():
    g = ae.AIEvaluation()
    asm = g.assess("sys-a", 1, assessment_digest=PIN)
    g.evaluate("asm-1", 2, evaluation_digest=PIN)
    rep = g.verify("asm-1", 3)
    assert rep.record_kind == "assessment"
    assert rep.verdict == "verified"
    assert rep.verify()
    rep2 = g.verify("evl-1", 3)  # same seq twice: pure read, no consumption
    assert rep2.record_kind == "evaluation"
    assert rep2.verdict == "verified"
    assert len(g.audit_log(4)) == 2  # no audit row for reads
    # tamper-as-data: replace a stored record with a corrupted twin
    tampered = ae.AssessmentRecord(
        assessment_id=asm.assessment_id,
        system_id=asm.system_id,
        assessment_kind=asm.assessment_kind,
        finding="fail",
        severity=asm.severity,
        assessment_digest=asm.assessment_digest,
        digest=asm.digest,
    )
    g._assessments["asm-1"] = tampered
    rep3 = g.verify("asm-1", 5)
    assert rep3.verdict == "tampered"
    with pytest.raises(ae.UnknownAssessmentError):
        g.verify("asm-999", 6)
    with pytest.raises(ae.SeqOrderError):
        g.verify("asm-1", 0)  # seq shape validated even on reads


# 11. retire terminality + id non-recycling + post-retire reads
def test_retire_terminality():
    g = ae.AIEvaluation()
    g.assess("sys-a", 1, assessment_digest=PIN)
    g.evaluate("asm-1", 2, evaluation_digest=PIN)
    with pytest.raises(ae.BadReasonError):
        g.retire("sys-a", 3, reason="bogus")
    rec = g.retire("sys-a", 4, reason="decommissioned")
    assert rec.system_id == "sys-a"
    assert rec.verify()
    with pytest.raises(ae.RetiredSystemError):
        g.retire("sys-a", 5)
    with pytest.raises(ae.RetiredSystemError):
        g.assess("sys-a", 6, assessment_digest=PIN)
    # ids never recycled, but reads still work
    assert g.retired_ids(7) == ("sys-a",)
    assert g.system_ids(8) == ("sys-a",)
    assert g.assessments_for("sys-a", 9) == ("asm-1",)
    assert g.evaluations_for("sys-a", 10) == ("evl-1",)
    assert g.assessment_record("asm-1", 11).finding == "not-assessed"
    assert g.evaluation_record("evl-1", 12).outcome == "inconclusive"


# 12. seq discipline: genesis rewind bare, malformed seqs, burn
def test_seq_discipline():
    g = ae.AIEvaluation()
    with pytest.raises(ae.SeqOrderError):
        g.assess("sys-a", 0, assessment_digest=PIN)
    with pytest.raises(ae.SeqOrderError):
        g.assess("sys-a", True, assessment_digest=PIN)
    with pytest.raises(ae.SeqOrderError):
        g.assess("sys-a", "1", assessment_digest=PIN)
    g.assess("sys-a", 1, assessment_digest=PIN)
    # rewind raises bare with zero new audit rows
    n = len(g.audit_log(999))
    with pytest.raises(ae.SeqOrderError):
        g.assess("sys-b", 1, assessment_digest=PIN)
    assert len(g.audit_log(999)) == n
    # failed mutation consumes its seq
    with pytest.raises(ae.BadAssessmentKindError):
        g.assess("sys-b", 2, assessment_kind="bogus", assessment_digest=PIN)
    with pytest.raises(ae.SeqOrderError):
        g.assess("sys-b", 2, assessment_digest=PIN)
    g.assess("sys-b", 3, assessment_digest=PIN)
    assert g.system_ids(999) == ("sys-a", "sys-b")


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    g = ae.AIEvaluation()
    g.assess("sys-a", 1, assessment_digest=PIN)
    g.evaluate("asm-1", 2, evaluation_digest=PIN)
    rows = g.audit_log(3)
    assert [r["kind"] for r in rows] == ["assessed", "evaluated"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert isinstance(r["seq"], int)
        assert isinstance(r["details"], dict)
    assert rows[0]["details"]["assessment_kind"] == "safety-eval"
    assert rows[1]["details"]["outcome"] == "inconclusive"
    # banned raw-material keys cannot cross the audit boundary
    with pytest.raises(ae.AuditKindError):
        ae.ai_evaluation_audit_event("assessed", 4, scores=[1, 2, 3])
    with pytest.raises(ae.AuditKindError):
        ae.ai_evaluation_audit_event("evaluated", 4, transcripts=["x"])
    with pytest.raises(ae.AuditKindError):
        ae.ai_evaluation_audit_event("bogus-kind", 4)
    with pytest.raises(ae.SeqOrderError):
        ae.ai_evaluation_audit_event("assessed", -1)


# 14. views/stats + cross-instance determinism + 8-thread read smoke
def test_views_stats_determinism_and_threads():
    g = ae.AIEvaluation()
    g.assess("sys-a", 1, assessment_digest=PIN)
    g.evaluate("asm-1", 2, evaluation_digest=PIN)
    stats = g.stats(3)
    assert stats == {
        "systems": 1,
        "assessments": 1,
        "evaluations": 1,
        "retired": 0,
        "rejected": 0,
    }
    # cross-instance digest determinism
    h = ae.AIEvaluation()
    rec_a = h.assess("sys-a", 1, assessment_digest=PIN)
    assert rec_a.digest == g.assessment_record("asm-1", 4).digest
    # unknown lookups
    with pytest.raises(ae.UnknownAssessmentError):
        g.assessment_record("asm-999", 5)
    with pytest.raises(ae.UnknownSystemError):
        g.assessments_for("nope", 5)
    # 8-thread concurrent read smoke
    errors = []

    def reader():
        try:
            for _ in range(50):
                g.assessment_record("asm-1", 6)
                g.verify("evl-1", 6)
        except Exception as exc:  # pragma: no cover - diagnostic
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() self-check subprocess
def test_main_self_check():
    import subprocess

    out = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == (
        "ai-evaluation OK: assess, evaluate, verify, retire, pins, audit"
    )
