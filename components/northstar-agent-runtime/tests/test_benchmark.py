"""15 tests for benchmark.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "benchmark.py"


def _load():
    spec = importlib.util.spec_from_file_location("benchmark", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["benchmark"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


bmk_mod = _load()

PIN = "sha256:" + "a" * 64


def _bmk():
    return bmk_mod.Benchmark()


# 1. version/schema pins
def test_pins():
    assert bmk_mod.BENCHMARK_VERSION == "benchmark.v1"
    assert bmk_mod.SCHEMA_PIN == "northstar.benchmark.v1"
    assert set(bmk_mod.TASK_KINDS) == {
        "capability", "safety", "robustness", "alignment",
        "reasoning", "tool-use", "agentic", "evaluation",
    }
    assert set(bmk_mod.RUN_OUTCOMES) == {
        "passed", "failed", "inconclusive", "not-run",
    }
    assert set(bmk_mod.POSTURES) == {
        "unrun", "passed", "failed", "partial", "inconclusive",
    }
    assert set(bmk_mod.RETIRE_REASONS) == {
        "manual", "superseded", "deprecated", "withdrawn",
    }


# 2. stdlib-only AST check (canonical_json is the in-repo sibling with stdlib fallback)
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    allowed = {
        "__future__", "threading", "dataclasses", "hashlib", "json",
        "fractions", "canonical_json",
    }
    assert imports <= allowed, imports - allowed


# 3. create roundtrip + verify + frozen-ness
def test_create_roundtrip():
    b = _bmk()
    r = b.create("bench-1", 1, task_kind="safety", benchmark_digest=PIN)
    assert r.benchmark_id == "bench-1"
    assert r.task_kind == "safety"
    assert r.verify()
    assert r.as_dict()["schema"] == "northstar.benchmark.v1"
    with pytest.raises(Exception):
        r.task_kind = "capability"  # frozen
    got = b.benchmark_record("bench-1", 2)
    assert got.verify()
    with pytest.raises(bmk_mod.UnknownBenchmarkError):
        b.benchmark_record("ghost", 2)


# 4. create bad inputs + seq-burn + rejected rows
def test_create_bad_inputs():
    b = _bmk()
    seq = 0
    bad = [
        (lambda q: b.create("", q), bmk_mod.BadIdError),
        (lambda q: b.create("b", q, task_kind="vibes"), bmk_mod.BadKindError),
        (lambda q: b.create("b", q, benchmark_digest="raw-bytes"),
         bmk_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert b.stats(seq + 1)["rejected"] == len(bad)
    assert len(b.audit_log(seq + 1)) == len(bad)
    # duplicate refused (consumes seq, books rejected row)
    b.create("b1", seq + 2)
    with pytest.raises(bmk_mod.DuplicateBenchmarkError):
        b.create("b1", seq + 3)
    assert b.stats(seq + 4)["rejected"] == len(bad) + 1


# 5. all task kinds acceptance
def test_all_task_kinds():
    b = _bmk()
    seq = 0
    for i, kind in enumerate(bmk_mod.TASK_KINDS):
        seq += 1
        r = b.create(f"bench-{i}", seq, task_kind=kind)
        assert r.verify()
    assert len(b.benchmark_ids(seq + 1)) == len(bmk_mod.TASK_KINDS)


# 6. run roundtrip
def test_run_roundtrip():
    b = _bmk()
    b.create("bench-1", 1)
    r = b.run("bench-1", 2, outcome="passed", score=88, result_digest=PIN)
    assert r.run_id == "run-1"
    assert r.verify()
    assert r.as_dict()["score"] == 88
    with pytest.raises(bmk_mod.UnknownRecordError):
        b.run_record("run-99", 3)
    assert b.runs_for("bench-1", 3) == ("run-1",)
    with pytest.raises(bmk_mod.UnknownBenchmarkError):
        b.runs_for("ghost", 3)


# 7. run bad inputs
def test_run_bad_inputs():
    b = _bmk()
    b.create("bench-1", 1)
    seq = 1
    bad = [
        (lambda q: b.run("", q), bmk_mod.BadIdError),
        (lambda q: b.run("ghost", q), bmk_mod.UnknownBenchmarkError),
        (lambda q: b.run("bench-1", q, outcome="vibes"),
         bmk_mod.BadOutcomeError),
        (lambda q: b.run("bench-1", q, score=-1), bmk_mod.BadScoreError),
        (lambda q: b.run("bench-1", q, score=101), bmk_mod.BadScoreError),
        (lambda q: b.run("bench-1", q, score=True), bmk_mod.BadScoreError),
        (lambda q: b.run("bench-1", q, score=1.5), bmk_mod.BadScoreError),
        (lambda q: b.run("bench-1", q, result_digest="md5:abc"),
         bmk_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert b.stats(seq + 1)["rejected"] == len(bad)
    # full outcome vocabulary accepted
    for outcome in bmk_mod.RUN_OUTCOMES:
        seq += 1
        r = b.run("bench-1", seq, outcome=outcome)
        assert r.verify()


# 8. score posture math
def test_score_postures():
    b = _bmk()
    rep = b.score(1)
    assert rep.verify() and rep.posture == "unrun"
    b.create("a", 2)
    assert b.score(3, "a").posture == "unrun"
    b.run("a", 4, outcome="passed", score=90)
    b.run("a", 5, outcome="passed", score=70)
    rep = b.score(6, "a")
    assert rep.posture == "passed" and rep.mean_score == 80
    b.create("c", 7)
    b.run("c", 8, outcome="passed")
    b.run("c", 9, outcome="failed")
    assert b.score(10, "c").posture == "failed"
    b.create("d", 11)
    b.run("d", 12, outcome="inconclusive")
    assert b.score(13, "d").posture == "inconclusive"
    b.create("e", 14)
    b.run("e", 15, outcome="passed")
    b.run("e", 16, outcome="inconclusive")
    assert b.score(17, "e").posture == "partial"
    # whole-ledger: any failed beats everything
    assert b.score(18).posture == "failed"
    with pytest.raises(bmk_mod.UnknownBenchmarkError):
        b.score(19, "ghost")
    rep = b.score(20)
    assert rep.verify() and rep.n_benchmarks == 4


# 9. retire terminality + id non-recycling
def test_retire_terminality():
    b = _bmk()
    b.create("bench-1", 1)
    rec = b.retire("bench-1", 2, reason="superseded")
    assert rec.verify() and b.retired_ids(3) == ("bench-1",)
    with pytest.raises(bmk_mod.RetiredBenchmarkError):
        b.run("bench-1", 4)  # post-retire mutations refused
    with pytest.raises(bmk_mod.RetiredBenchmarkError):
        b.create("bench-1", 5)  # ids never recycled
    with pytest.raises(bmk_mod.RetiredBenchmarkError):
        b.retire("bench-1", 6)  # double retire
    with pytest.raises(bmk_mod.BadReasonError):
        b.retire("bench-2", 7, reason="vibes")  # bad reason on unknown
    # reads still work after retirement
    assert b.benchmark_record("bench-1", 8).verify()
    b.create("bench-2", 9)
    b.retire("bench-2", 10)
    assert b.retired_ids(11) == ("bench-1", "bench-2")


# 10. seq discipline: rewind bare, malformed, burn accounting
def test_seq_discipline():
    b = _bmk()
    b.create("b1", 1)
    with pytest.raises(bmk_mod.SeqOrderError):
        b.create("b2", 1)  # rewind: bare, no rejected row
    assert b.stats(2)["rejected"] == 0
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(bmk_mod.SeqOrderError):
            b.run("b1", bad)
    b.run("b1", 3)
    # failed mutation consumes its seq + books a rejected row
    with pytest.raises(bmk_mod.BadOutcomeError):
        b.run("b1", 4, outcome="vibes")
    assert b.stats(5)["rejected"] == 1
    assert b.stats(5)["seq"] == 4


# 11. view purity and stats
def test_view_purity_and_stats():
    b = _bmk()
    b.create("b1", 1)
    b.run("b1", 2)
    b.retire("b1", 3)
    n_audit = len(b.audit_log(4))
    assert b.benchmark_ids(4) == ("b1",)
    assert b.runs_for("b1", 4) == ("run-1",)
    assert b.retired_ids(4) == ("b1",)
    assert len(b.audit_log(4)) == n_audit  # reads add no rows
    st = b.stats(4)
    assert st == {"benchmarks": 1, "runs": 1, "retired": 1,
                  "rejected": 0, "audit_rows": 3, "seq": 3}
    with pytest.raises(bmk_mod.SeqOrderError):
        b.benchmark_ids(0)  # read seq must be positive int


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    b = _bmk()
    b.create("b1", 1, task_kind="safety")
    b.run("b1", 2, outcome="passed", score=75)
    b.retire("b1", 3)
    rows = b.audit_log(4)
    assert [r["kind"] for r in rows] == ["benchmark.created",
                                        "benchmark.run", "benchmark.retired"]
    for row in rows:
        assert set(row) == {"kind", "details"}
        for key in row["details"]:
            assert key not in bmk_mod._BANNED_AUDIT_KEYS
    with pytest.raises(bmk_mod.AuditKindError):
        bmk_mod.benchmark_audit_event("bogus-kind", {})
    with pytest.raises(bmk_mod.AuditKindError):
        bmk_mod.benchmark_audit_event("created", {"prompt": "raw"})  # banned
    with pytest.raises(bmk_mod.AuditKindError):
        bmk_mod.benchmark_audit_event("created", "not-a-dict")


# 13. digest determinism + tamper + concurrency
def test_digest_and_concurrency():
    def build():
        b = bmk_mod.Benchmark()
        b.create("b1", 1, task_kind="alignment")
        b.run("b1", 2, outcome="passed", score=90)
        return b
    b1, b2 = build(), build()
    assert b1.run_record("run-1", 3).digest == b2.run_record("run-1", 3).digest
    import dataclasses
    rec = b1.run_record("run-1", 3)
    tampered = dataclasses.replace(rec, outcome="failed")
    assert tampered.verify() is False
    object.__setattr__(rec, "outcome", "failed")
    assert rec.verify() is False
    # cross-instance determinism on the derived score report too
    b3, b4 = build(), build()
    assert b3.score(3, "b1").digest == b4.score(3, "b1").digest
    # 8-thread read smoke
    b = build()
    results = []
    def worker():
        results.append(b.score(3, "b1").posture)
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["passed"] * 8


# 14. run minting + not-run outcome + mean math edge
def test_run_minting_and_mean():
    b = _bmk()
    b.create("b1", 1)
    r1 = b.run("b1", 2)
    r2 = b.run("b1", 3, outcome="not-run")
    assert (r1.run_id, r2.run_id) == ("run-1", "run-2")
    assert b.score(4, "b1").posture == "partial"
    b.create("b2", 5)
    b.run("b2", 6, score=81)
    b.run("b2", 7, score=80)
    assert b.score(8, "b2").mean_score == 81  # 80.5 rounds half up


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD_PATH)],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "benchmark OK: create, run, score, retire, pins, audit"
    )
