"""15 targeted tests for alignment_eval (house style: pytest, exact spec)."""

from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from alignment_eval import (
    ALIGNMENT_EVAL_SCHEMA,
    ALIGNMENT_EVAL_VERSION,
    CAT_DECEPTION,
    CAT_CORRIGIBILITY,
    CAT_SYCOPHANCY,
    GRADE_FAIL,
    GRADE_INCONCLUSIVE,
    GRADE_PASS,
    VERDICT_ALIGNED,
    VERDICT_AMBIGUOUS,
    VERDICT_MISALIGNED,
    AlignmentEval,
    AlignmentEvalError,
    AuditKindError,
    BadCategoryError,
    BadDigestError,
    BadJudgmentError,
    BadScenarioError,
    BadVerdictError,
    DuplicateGradeError,
    DuplicateScenarioError,
    EmptyJudgmentsError,
    GradeReport,
    JudgmentRecord,
    ScenarioRecord,
    SeqOrderError,
    UnknownGradeError,
    UnknownJudgmentError,
    UnknownScenarioError,
    _digest_pin,
    alignment_eval_audit_event,
)


def _d(*parts):
    return _digest_pin(tuple(parts), "probe")


# ---------------------------------------------------------------------------
# 1. version / schema pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert ALIGNMENT_EVAL_VERSION == "alignment-eval.v1"
    assert ALIGNMENT_EVAL_SCHEMA == "northstar.alignment-eval.v1"
    rec = AlignmentEval().scenario("s", CAT_DECEPTION, _d("q"), 1)
    assert isinstance(rec, ScenarioRecord)
    assert rec.schema == ALIGNMENT_EVAL_SCHEMA
    assert rec.verify()


# ---------------------------------------------------------------------------
# 2. stdlib-only AST check
# ---------------------------------------------------------------------------


def test_stdlib_only_ast():
    src = Path(__file__).parent.with_name("alignment_eval.py").read_text()
    tree = ast.parse(src)
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "__future__",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 3. scenario roundtrip
# ---------------------------------------------------------------------------


def test_scenario_roundtrip():
    ledger = AlignmentEval()
    rec = ledger.scenario("s1", CAT_CORRIGIBILITY, _d("prompt"), 1)
    assert rec.scenario_id == "s1"
    assert rec.category == CAT_CORRIGIBILITY
    assert rec.prompt_digest == _d("prompt")
    assert rec.verify()
    got = ledger.scenario_record("s1", 2)
    assert got == rec
    assert ledger.scenario_ids(2) == ("s1",)


# ---------------------------------------------------------------------------
# 4. scenario bad inputs + seq-burn + rejected rows
# ---------------------------------------------------------------------------


def test_scenario_bad_inputs():
    ledger = AlignmentEval()
    seq = 0
    before = len(ledger.audit_log(1))

    def nxt():
        nonlocal seq
        seq += 1
        return seq

    bad_cases = [
        ("", CAT_DECEPTION, _d("q")),  # empty id
        (123, CAT_DECEPTION, _d("q")),  # non-str id
        (True, CAT_DECEPTION, _d("q")),  # bool id
        ("s", "unknown-cat", _d("q")),  # bad category
        ("s", 42, _d("q")),  # non-str category
        ("s", CAT_DECEPTION, "no-prefix"),  # bad digest
        ("s", CAT_DECEPTION, ""),  # empty digest
        ("s", CAT_DECEPTION, _d("q") + "x" * 512),  # too long
    ]
    rejected = 0
    for sid, cat, dg in bad_cases:
        with pytest.raises(AlignmentEvalError):
            ledger.scenario(sid, cat, dg, nxt())
        rejected += 1
    # duplicate refusal
    ledger.scenario("dup", CAT_SYCOPHANCY, _d("q"), nxt())
    with pytest.raises(DuplicateScenarioError):
        ledger.scenario("dup", CAT_SYCOPHANCY, _d("q"), nxt())
    rejected += 1
    after = len(ledger.audit_log(nxt()))
    # 8 bad-input rows + 1 duplicate row; the +1 is the successful "dup" row
    assert after - before == rejected + 1
    kinds = [e["kind"] for e in ledger.audit_log(nxt())]
    assert kinds.count("alignment-eval.rejected") == rejected


# ---------------------------------------------------------------------------
# 5. judge roundtrip + booking order
# ---------------------------------------------------------------------------


def test_judge_roundtrip():
    ledger = AlignmentEval()
    ledger.scenario("s1", CAT_DECEPTION, _d("q"), 1)
    j1 = ledger.judge("s1", VERDICT_ALIGNED, 2)
    j2 = ledger.judge("s1", VERDICT_MISALIGNED, 3, judge_digest=_d("why"))
    assert isinstance(j1, JudgmentRecord)
    assert j1.judgment_id == "judg-1" and j2.judgment_id == "judg-2"
    assert j1.verify() and j2.verify()
    assert ledger.judgments_for("s1", 4) == ("judg-1", "judg-2")
    assert ledger.judgment_record("judg-1", 4) == j1


# ---------------------------------------------------------------------------
# 6. judge bad inputs + unknown scenario
# ---------------------------------------------------------------------------


def test_judge_bad_inputs():
    ledger = AlignmentEval()
    ledger.scenario("s1", CAT_DECEPTION, _d("q"), 1)
    with pytest.raises(UnknownScenarioError):
        ledger.judge("nope", VERDICT_ALIGNED, 2)
    with pytest.raises(BadVerdictError):  # bad verdict vocabulary
        ledger.judge("s1", "kinda-aligned", 3)
    with pytest.raises(BadVerdictError):  # non-str verdict
        ledger.judge("s1", None, 4)
    with pytest.raises(BadDigestError):  # malformed judge digest
        ledger.judge("s1", VERDICT_ALIGNED, 5, judge_digest="bare")
    # no rejected-row counting needed here; just assert ledger is untouched
    assert ledger.judgments_for("s1", 6) == ()


# ---------------------------------------------------------------------------
# 7. grade pass rule
# ---------------------------------------------------------------------------


def test_grade_pass():
    ledger = AlignmentEval()
    ledger.scenario("s1", CAT_CORRIGIBILITY, _d("q"), 1)
    ledger.judge("s1", VERDICT_ALIGNED, 2)
    ledger.judge("s1", VERDICT_ALIGNED, 3)
    ledger.judge("s1", VERDICT_AMBIGUOUS, 4)
    report = ledger.grade("s1", 5)
    assert isinstance(report, GradeReport)
    assert report.verify()
    assert report.grade == GRADE_PASS
    assert (report.aligned, report.misaligned, report.ambiguous) == (2, 0, 1)
    assert report.judgment_count == 3
    assert ledger.grade_report("s1", 6) == report


# ---------------------------------------------------------------------------
# 8. grade fail rule (any misaligned fails)
# ---------------------------------------------------------------------------


def test_grade_fail():
    ledger = AlignmentEval()
    ledger.scenario("s1", CAT_DECEPTION, _d("q"), 1)
    for i, v in enumerate((VERDICT_ALIGNED, VERDICT_ALIGNED, VERDICT_MISALIGNED), 2):
        ledger.judge("s1", v, i)
    report = ledger.grade("s1", 5)
    assert report.grade == GRADE_FAIL
    assert report.verify()


# ---------------------------------------------------------------------------
# 9. grade inconclusive rule + terminality
# ---------------------------------------------------------------------------


def test_grade_inconclusive_and_terminal():
    ledger = AlignmentEval()
    ledger.scenario("s1", CAT_SYCOPHANCY, _d("q"), 1)
    ledger.judge("s1", VERDICT_ALIGNED, 2)
    ledger.judge("s1", VERDICT_AMBIGUOUS, 3)
    report = ledger.grade("s1", 4)
    assert report.grade == GRADE_INCONCLUSIVE  # 1 aligned vs 1 not -> no strict majority
    # grading is terminal
    with pytest.raises(DuplicateGradeError):
        ledger.grade("s1", 5)
    # judgments close once graded
    with pytest.raises(BadJudgmentError):
        ledger.judge("s1", VERDICT_ALIGNED, 6)
    # ungraded scenario raises on grade_report
    ledger.scenario("s2", CAT_DECEPTION, _d("q2"), 7)
    with pytest.raises(UnknownGradeError):
        ledger.grade_report("s2", 8)


# ---------------------------------------------------------------------------
# 10. grade empty judgments refused fail-closed
# ---------------------------------------------------------------------------


def test_grade_empty_judgments_refused():
    ledger = AlignmentEval()
    ledger.scenario("s1", CAT_DECEPTION, _d("q"), 1)
    with pytest.raises(EmptyJudgmentsError):
        ledger.grade("s1", 2)
    with pytest.raises(UnknownScenarioError):
        ledger.grade("ghost", 3)


# ---------------------------------------------------------------------------
# 11. seq discipline (rewind bare, malformed seqs)
# ---------------------------------------------------------------------------


def test_seq_discipline():
    ledger = AlignmentEval()
    ledger.scenario("s1", CAT_DECEPTION, _d("q"), 5)
    # rewind raises bare SeqOrderError and consumes nothing
    before = len(ledger.audit_log(6))
    with pytest.raises(SeqOrderError):
        ledger.scenario("s2", CAT_DECEPTION, _d("q"), 5)
    with pytest.raises(SeqOrderError):
        ledger.scenario("s2", CAT_DECEPTION, _d("q"), 3)
    assert len(ledger.audit_log(6)) == before
    # malformed seqs
    for bad in (True, "7", 2.5, None):
        with pytest.raises(SeqOrderError):
            ledger.scenario("s3", CAT_DECEPTION, _d("q"), bad)
    # failed-mutation-consumes-seq: next valid seq must advance past failures
    with pytest.raises(DuplicateScenarioError):
        ledger.scenario("s1", CAT_DECEPTION, _d("q"), 7)
    with pytest.raises(SeqOrderError):
        ledger.scenario("s4", CAT_DECEPTION, _d("q"), 7)  # 7 was consumed by the failure


# ---------------------------------------------------------------------------
# 12. audit shapes + banned-key leak ban + bad kind
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    ledger = AlignmentEval()
    ledger.scenario("s1", CAT_DECEPTION, _d("q"), 1)
    ledger.judge("s1", VERDICT_ALIGNED, 2)
    ledger.grade("s1", 3)
    events = ledger.audit_log(4)
    kinds = [e["kind"] for e in events]
    assert kinds == [
        "alignment-eval.scenario-registered",
        "alignment-eval.judgment-booked",
        "alignment-eval.graded",
    ]
    for e in events:
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "alignment-eval"
    with pytest.raises(AuditKindError):
        alignment_eval_audit_event("nope.kind", 1)
    with pytest.raises(AuditKindError):
        alignment_eval_audit_event("alignment-eval.scenario-registered", 1, prompt="raw text")
    with pytest.raises(AuditKindError):
        alignment_eval_audit_event("alignment-eval.judgment-booked", 1, rationale="leak")


# ---------------------------------------------------------------------------
# 13. cross-instance digest determinism
# ---------------------------------------------------------------------------


def test_cross_instance_determinism():
    def build():
        ledger = AlignmentEval()
        ledger.scenario("s1", CAT_DECEPTION, _d("q"), 1)
        ledger.judge("s1", VERDICT_ALIGNED, 2)
        ledger.judge("s1", VERDICT_AMBIGUOUS, 3)
        return ledger.grade("s1", 4)

    r1, r2 = build(), build()
    assert r1.digest == r2.digest
    assert r1.grade == r2.grade == GRADE_INCONCLUSIVE
    assert r1.verify() and r2.verify()


# ---------------------------------------------------------------------------
# 14. views purity (no seq consumption, no audit rows)
# ---------------------------------------------------------------------------


def test_views_purity():
    ledger = AlignmentEval()
    ledger.scenario("s1", CAT_DECEPTION, _d("q"), 1)
    ledger.judge("s1", VERDICT_ALIGNED, 2)
    n0 = len(ledger.audit_log(3))
    # same seq reuse is fine for reads
    assert ledger.scenario_ids(4) == ledger.scenario_ids(4) == ("s1",)
    assert ledger.judgments_for("s1", 4) == ("judg-1",)
    assert ledger.stats(4)["scenarios"] == 1
    assert ledger.stats(4)["judgments"] == 1
    assert len(ledger.audit_log(4)) == n0  # no audit rows from reads


# ---------------------------------------------------------------------------
# 15. concurrency smoke + main() subprocess
# ---------------------------------------------------------------------------


def test_concurrency_and_main():
    ledger = AlignmentEval()
    errors = []

    def worker(i):
        try:
            ledger.scenario(f"s{i}", CAT_DECEPTION, _d(f"q{i}"), i + 1)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(ledger.scenario_ids(9)) == 8

    mod_path = Path(__file__).parent.with_name("alignment_eval.py")
    proc = subprocess.run(
        [sys.executable, str(mod_path)],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(mod_path.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "alignment-eval OK" in proc.stdout
