"""Tests for the AI-benchmarking decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_benchmarking.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_benchmarking", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_benchmarking"] = module
    spec.loader.exec_module(module)
    return module


ab = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ab.AI_BENCHMARKING_VERSION == "ai-benchmarking.v1"
    assert ab.SCHEMA_PIN == "northstar.ai-benchmarking.v1"
    assert ab.BENCHMARK_KINDS == (
        "capability",
        "safety",
        "alignment",
        "robustness",
        "fairness",
        "efficiency",
        "security",
        "governance",
    )
    assert ab.OUTCOMES == (
        "pass",
        "fail",
        "partial",
        "inconclusive",
        "not-evaluated",
    )
    assert ab.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert ab.VERIFY_VERDICTS == (
        "verified",
        "tampered",
    )
    assert set(ab.AUDIT_KINDS) == {
        "benchmarked",
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


# 3. benchmark roundtrip + verify()
def test_benchmark_roundtrip_and_verify():
    g = ab.AIBenchmarking()
    rec = g.benchmark(
        "sys-a", "suite-1", 1,
        benchmark_kind="safety", outcome="pass", score=92, suite_digest=PIN,
    )
    assert rec.benchmark_id == "bmk-1"
    assert rec.system_id == "sys-a"
    assert rec.suite_id == "suite-1"
    assert rec.benchmark_kind == "safety"
    assert rec.outcome == "pass"
    assert rec.score == 92
    assert rec.suite_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.ai-benchmarking.v1"
    fetched = g.benchmark_record("bmk-1", 2)
    assert fetched == rec
    rep = g.verify("bmk-1", 3)
    assert rep.verdict == "verified"
    assert rep.record_kind == "benchmark"
    assert rep.verify()
    assert g.system_ids(4) == ("sys-a",)
    assert g.benchmark_ids(5) == ("bmk-1",)
    assert g.benchmarks_for("sys-a", 6) == ("bmk-1",)


# 4. benchmark bad-input table + seq-burn + rejected rows
def test_benchmark_bad_inputs_and_seq_burn():
    g = ab.AIBenchmarking()
    bad = [
        ("", "suite-1", "capability", "pass", 50, PIN),                 # empty id
        ("x" * 129, "suite-1", "capability", "pass", 50, PIN),          # too long
        (None, "suite-1", "capability", "pass", 50, PIN),               # non-str id
        ("ok-1", "", "capability", "pass", 50, PIN),                    # empty suite
        ("ok-1", "suite-1", "not-a-kind", "pass", 50, PIN),            # bad kind
        ("ok-1", "suite-1", "capability", "not-an-outcome", 50, PIN),   # bad outcome
        ("ok-1", "suite-1", "capability", "pass", -1, PIN),            # score < 0
        ("ok-1", "suite-1", "capability", "pass", 101, PIN),            # score > 100
        ("ok-1", "suite-1", "capability", "pass", True, PIN),           # bool score
        ("ok-1", "suite-1", "capability", "pass", 50, "not-a-pin"),     # bad digest
        ("ok-1", "suite-1", "capability", "pass", 50, "sha256:zzz"),   # bad hex
    ]
    seq = 1
    rejected_before = g.stats(1)["rejected"]
    assert rejected_before == 0
    for sid, suite, kind, outcome, score, digest in bad:
        seq += 1
        with pytest.raises(ab.AIBenchmarkingError):
            g.benchmark(sid, suite, seq, benchmark_kind=kind,
                        outcome=outcome, score=score, suite_digest=digest)
    assert g.stats(seq + 1)["rejected"] == len(bad)
    assert g.stats(seq + 2)["benchmarks"] == 0
    rows = g.audit_log(seq + 3)
    rejected_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected_rows) == len(bad)
    assert all(r["details"]["method"] == "benchmark" for r in rejected_rows)
    # rewind raises bare with zero new rows
    before = len(rows)
    with pytest.raises(ab.SeqOrderError):
        g.benchmark("ok-1", "suite-1", 1, suite_digest=PIN)
    assert len(g.audit_log(seq + 4)) == before


# 5. full 8-kind vocabulary accepted
def test_full_benchmark_kind_vocabulary():
    g = ab.AIBenchmarking()
    for i, kind in enumerate(ab.BENCHMARK_KINDS):
        rec = g.benchmark(
            "sys-k", f"suite-{i}", i + 1, benchmark_kind=kind,
            outcome="pass", score=75, suite_digest=PIN,
        )
        assert rec.benchmark_kind == kind
        assert rec.verify()
    assert g.stats(len(ab.BENCHMARK_KINDS) + 1)["benchmarks"] == len(ab.BENCHMARK_KINDS)


# 6. full 5-outcome vocabulary + score 0/100 bounds
def test_full_outcome_vocabulary_and_score_bounds():
    g = ab.AIBenchmarking()
    for i, outcome in enumerate(ab.OUTCOMES):
        rec = g.benchmark(
            "sys-o", f"suite-{i}", i + 1, outcome=outcome,
            score=0 if i == 0 else 100, suite_digest=PIN,
        )
        assert rec.outcome == outcome
        assert rec.verify()
    ev = g.evaluate("sys-o", 6)
    assert ev.n_pass == 1
    assert ev.n_fail == 1
    assert ev.n_partial == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_evaluated == 1
    assert ev.avg_score == pytest.approx(80.0)
    # score bounds are the defaults-adjacent edges
    rec = g.benchmark("sys-o", "suite-edge", 7, score=0, suite_digest=PIN)
    assert rec.score == 0
    rec = g.benchmark("sys-o", "suite-edge2", 8, score=100, suite_digest=PIN)
    assert rec.score == 100


# 7. verify semantics: verified + tamper-as-data + unknown refusal + read purity
def test_verify_semantics():
    g = ab.AIBenchmarking()
    rec = g.benchmark("sys-v", "suite-1", 1, outcome="pass",
                      score=80, suite_digest=PIN)
    before = len(g.audit_log(2))
    rep = g.verify("bmk-1", 3)
    assert rep.verdict == "verified"
    assert rep.verify()
    assert len(g.audit_log(4)) == before  # pure read: no audit row
    assert g.stats(5)["benchmarks"] == 1
    # unknown benchmark refuses
    with pytest.raises(ab.UnknownBenchmarkError):
        g.verify("bmk-999", 6)
    # tampered record -> verdict "tampered" as data, never raised
    object.__setattr__(rec, "score", 1)
    rep = g.verify("bmk-1", 7)
    assert rep.verdict == "tampered"
    assert rep.verify()


# 8. evaluate posture math: all postures + precedence + tallies
def test_evaluate_posture_math():
    g = ab.AIBenchmarking()
    # empty system -> unevaluated
    g.benchmark("sys-e", "suite-0", 1, outcome="not-evaluated",
                score=0, suite_digest=PIN)
    ev = g.evaluate("sys-e", 2)
    assert ev.posture == "partial"
    assert ev.n_benchmarks == 1
    # fresh system: passing only
    g.benchmark("sys-p", "suite-1", 3, outcome="pass",
                score=90, suite_digest=PIN)
    ev = g.evaluate("sys-p", 4)
    assert ev.posture == "passing"
    assert ev.integrity_ok is True
    assert ev.verify()
    # partial outranks nothing except failing/contested above it
    g.benchmark("sys-p", "suite-2", 5, outcome="partial",
                score=60, suite_digest=PIN2)
    ev = g.evaluate("sys-p", 6)
    assert ev.posture == "partial"
    assert ev.n_partial == 1
    # inconclusive outranks partial
    g.benchmark("sys-p", "suite-3", 7, outcome="inconclusive",
                score=0, suite_digest=PIN3)
    ev = g.evaluate("sys-p", 8)
    assert ev.posture == "contested"
    # fail outranks everything
    g.benchmark("sys-p", "suite-4", 9, outcome="fail",
                score=12, suite_digest=PIN)
    ev = g.evaluate("sys-p", 10)
    assert ev.posture == "failing"
    assert ev.n_fail == 1
    assert ev.n_benchmarks == 4
    assert ev.avg_score == pytest.approx((90 + 60 + 0 + 12) / 4)


# 9. evaluate read purity + unknown-system refusal + tamper flips integrity_ok
def test_evaluate_purity_and_integrity():
    g = ab.AIBenchmarking()
    g.benchmark("sys-i", "suite-1", 1, outcome="pass",
                score=88, suite_digest=PIN)
    before = len(g.audit_log(2))
    ev = g.evaluate("sys-i", 3)
    assert ev.posture == "passing"
    assert len(g.audit_log(4)) == before  # pure read: no audit row
    assert ev.verify()
    # unknown system refuses
    with pytest.raises(ab.UnknownSystemError):
        g.evaluate("no-such-system", 5)
    # tamper flips integrity_ok as data, posture unchanged (score is not
    # a posture field, so the ledger posture stays the same)
    rec = g.benchmark_record("bmk-1", 6)
    object.__setattr__(rec, "score", 1)
    ev = g.evaluate("sys-i", 7)
    assert ev.integrity_ok is False
    assert ev.posture == "passing"
    rep = g.verify("bmk-1", 8)
    assert rep.verdict == "tampered"


# 10. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    g = ab.AIBenchmarking()
    g.benchmark("sys-r", "suite-1", 1, outcome="pass",
                score=70, suite_digest=PIN)
    rec = g.retire("sys-r", 2, reason="superseded")
    assert rec.system_id == "sys-r"
    assert rec.reason == "superseded"
    assert rec.verify()
    assert g.retired_ids(3) == ("sys-r",)
    # double-retire refuses (seq burned, rejected row)
    with pytest.raises(ab.RetiredSystemError):
        g.retire("sys-r", 4)
    assert g.stats(5)["rejected"] == 1
    # post-retire mutation refuses: id never recycled
    with pytest.raises(ab.RetiredSystemError):
        g.benchmark("sys-r", "suite-2", 6, suite_digest=PIN)
    # bad reason burns seq
    g2 = ab.AIBenchmarking()
    g2.benchmark("sys-x", "suite-1", 1, suite_digest=PIN)
    with pytest.raises(ab.BadReasonError):
        g2.retire("sys-x", 2, reason="nope")
    assert g2.stats(3)["retired"] == 0
    # reads still work post-retire
    assert g.benchmark_record("bmk-1", 7).benchmark_id == "bmk-1"
    ev = g.evaluate("sys-r", 8)
    assert ev.posture == "passing"
    assert g.verify("bmk-1", 9).verdict == "verified"


# 11. seq discipline: genesis rewind bare + malformed seqs + failed-mutation-consumes-seq
def test_seq_discipline():
    g = ab.AIBenchmarking()
    # genesis rewind: seq 0 raises bare with zero rows
    with pytest.raises(ab.SeqOrderError):
        g.benchmark("sys-s", "suite-1", 0, suite_digest=PIN)
    assert g.stats(1)["rejected"] == 0
    assert g.audit_log(2) == ()
    # malformed seqs raise bare, consume nothing
    for bad_seq in (-1, True, 1.5, "3", None):
        with pytest.raises(ab.SeqOrderError):
            g.benchmark("sys-s", "suite-1", bad_seq, suite_digest=PIN)
    assert g.stats(3)["rejected"] == 0
    assert g.audit_log(4) == ()
    # valid mutation, then rewind raises bare without consuming
    g.benchmark("sys-s", "suite-1", 1, suite_digest=PIN)
    before = len(g.audit_log(2))
    with pytest.raises(ab.SeqOrderError):
        g.benchmark("sys-s", "suite-2", 1, suite_digest=PIN)
    assert len(g.audit_log(3)) == before
    assert g.stats(4)["rejected"] == 0
    # failed mutation consumes seq: next valid seq must be higher
    with pytest.raises(ab.BadBenchmarkKindError):
        g.benchmark("sys-s", "suite-2", 2, benchmark_kind="nope",
                    suite_digest=PIN)
    assert g.stats(3)["rejected"] == 1
    rec = g.benchmark("sys-s", "suite-2", 3, suite_digest=PIN)
    assert rec.benchmark_id == "bmk-2"


# 12. audit shapes + leak ban + bad-kind + pinned-data passthrough
def test_audit_shapes_and_leak_ban():
    g = ab.AIBenchmarking()
    rec = g.benchmark("sys-a", "suite-1", 1, benchmark_kind="safety",
                      outcome="pass", score=91, suite_digest=PIN)
    g.retire("sys-a", 2, reason="manual")
    rows = g.audit_log(3)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["kind"] == "benchmarked"
    assert rows[0]["seq"] == 1
    assert rows[0]["details"]["benchmark_id"] == "bmk-1"
    assert rows[0]["details"]["score"] == 91  # declared scalar stays emittable
    assert rows[0]["details"]["outcome"] == "pass"
    assert rows[1]["kind"] == "retired"
    # banned raw keys are refused at the builder
    with pytest.raises(ab.AuditKindError):
        ab.ai_benchmarking_audit_event(
            "benchmarked", 0, answers="leaked", benchmark_id="bmk-1")
    with pytest.raises(ab.AuditKindError):
        ab.ai_benchmarking_audit_event(
            "retired", 0, ground_truth="leaked", system_id="x")
    with pytest.raises(ab.AuditKindError):
        ab.ai_benchmarking_audit_event("nope-kind", 0)
    # pinned vocab values remain emittable as declared data
    row = ab.ai_benchmarking_audit_event(
        "benchmarked", 0, benchmark_kind="safety", outcome="pass", score=91)
    assert row["details"]["outcome"] == "pass"
    # digest pin survives verification roundtrip
    assert rec.verify()


# 13. views/stats + unknown lookups
def test_views_and_stats():
    g = ab.AIBenchmarking()
    g.benchmark("sys-1", "suite-a", 1, outcome="pass",
                score=80, suite_digest=PIN)
    g.benchmark("sys-2", "suite-b", 2, outcome="fail",
                score=20, suite_digest=PIN2)
    assert g.system_ids(3) == ("sys-1", "sys-2")
    assert g.benchmark_ids(4) == ("bmk-1", "bmk-2")
    assert g.benchmarks_for("sys-1", 5) == ("bmk-1",)
    assert g.stats(6) == {
        "systems": 2, "benchmarks": 2, "retired": 0, "rejected": 0}
    g.retire("sys-1", 7)
    assert g.stats(8)["retired"] == 1
    # unknown lookups refuse
    with pytest.raises(ab.UnknownBenchmarkError):
        g.benchmark_record("bmk-999", 9)
    with pytest.raises(ab.UnknownSystemError):
        g.benchmarks_for("ghost", 10)


# 14. cross-instance digest determinism + 8-thread read smoke
def test_determinism_and_thread_safety():
    g1 = ab.AIBenchmarking()
    g2 = ab.AIBenchmarking()
    r1 = g1.benchmark("sys-d", "suite-1", 1, benchmark_kind="robustness",
                      outcome="partial", score=55, suite_digest=PIN)
    r2 = g2.benchmark("sys-d", "suite-1", 1, benchmark_kind="robustness",
                      outcome="partial", score=55, suite_digest=PIN)
    assert r1.digest == r2.digest
    assert g1.evaluate("sys-d", 2).digest == g2.evaluate("sys-d", 2).digest
    errors = []

    def _read():
        try:
            for i in range(50):
                g1.benchmark_record("bmk-1", 10)
                g1.verify("bmk-1", 11)
                g1.evaluate("sys-d", 12)
                g1.stats(13)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # frozen records resist mutation
    with pytest.raises(Exception):
        r1.score = 1  # type: ignore


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "ai-benchmarking OK: benchmark, verify, evaluate, retire, pins, audit"
    )
