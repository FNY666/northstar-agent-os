"""15 tests for robustness_eval.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "robustness_eval.py"


def _load():
    spec = importlib.util.spec_from_file_location("robustness_eval", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["robustness_eval"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


re_mod = _load()

PIN = "sha256:" + "a" * 64


def _re():
    return re_mod.RobustnessEval()


# 1. version/schema pins
def test_pins():
    assert re_mod.ROBUSTNESS_EVAL_VERSION == "robustness-eval.v1"
    assert re_mod.SCHEMA_PIN == "northstar.robustness-eval.v1"
    assert set(re_mod.EVAL_KINDS) == {
        "adversarial", "distribution-shift", "corruption",
        "perturbation", "stress",
    }
    assert set(re_mod.ROBUSTNESS_DIMS) == {
        "adversarial-perturbations", "natural-shift",
        "common-corruptions", "edge-cases", "prompt-variants",
        "multi-modal-noise", "tool-noise", "time-drift",
    }
    assert set(re_mod.RUN_OUTCOMES) == {
        "robust", "degraded", "brittle", "inconclusive",
    }
    assert set(re_mod.POSTURES) == {
        "untested", "brittle-detected", "degraded", "robust",
        "inconclusive",
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
        "typing", "canonical_json",
    }
    assert imports <= allowed, imports - allowed


# 3. design roundtrip + verify + frozen-ness
def test_design_roundtrip():
    r = _re()
    d = r.design("sys-1", 1, eval_kind="corruption",
                 robustness_dim="common-corruptions", eval_digest=PIN)
    assert d.design_id == "dsg-1"
    assert d.system_id == "sys-1"
    assert d.verify()
    assert d.as_dict()["schema"] == "northstar.robustness-eval.v1"
    with pytest.raises(Exception):
        d.eval_kind = "stress"  # frozen
    got = r.design_record("dsg-1", 2)
    assert got.verify()
    with pytest.raises(re_mod.UnknownRecordError):
        r.design_record("dsg-99", 2)


# 4. design bad inputs + seq-burn + rejected rows
def test_design_bad_inputs():
    r = _re()
    seq = 0
    bad = [
        (lambda q: r.design("", q), re_mod.BadIdError),
        (lambda q: r.design("s", q, eval_kind="vibes"), re_mod.BadKindError),
        (lambda q: r.design("s", q, robustness_dim="vibes"), re_mod.BadDimError),
        (lambda q: r.design("s", q, eval_digest="raw-bytes"), re_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert r.stats(seq + 1)["rejected"] == len(bad)
    assert len(r.audit_log(seq + 1)) == len(bad)


# 5. all eval kinds and dims acceptance
def test_all_kinds_and_dims():
    r = _re()
    seq = 0
    for kind in re_mod.EVAL_KINDS:
        seq += 1
        r.design(f"sys-k-{kind}", seq, eval_kind=kind)
    for dim in re_mod.ROBUSTNESS_DIMS:
        seq += 1
        r.design(f"sys-d-{dim}", seq, robustness_dim=dim)
    assert r.stats(seq + 1)["designs"] == len(re_mod.EVAL_KINDS) + len(
        re_mod.ROBUSTNESS_DIMS)


# 6. run roundtrip + minted ids + unknown design
def test_run_roundtrip():
    r = _re()
    r.design("sys-1", 1)
    run = r.run("dsg-1", 2, outcome="degraded", score=45, run_digest=PIN)
    assert run.run_id == "run-1"
    assert run.design_id == "dsg-1"
    assert run.system_id == "sys-1"
    assert run.verify()
    got = r.run_record("run-1", 3)
    assert got.verify()
    with pytest.raises(re_mod.UnknownRecordError):
        r.run_record("run-99", 3)
    with pytest.raises(re_mod.UnknownRecordError):
        r.run("dsg-99", 4)  # seq consumed by the failed mutation


# 7. run bad inputs + seq-burn
def test_run_bad_inputs():
    r = _re()
    r.design("sys-1", 1)
    seq = 1
    bad = [
        (lambda q: r.run("", q), re_mod.BadIdError),
        (lambda q: r.run("dsg-1", q, outcome="vibes"), re_mod.BadOutcomeError),
        (lambda q: r.run("dsg-1", q, score=-1), re_mod.BadScoreError),
        (lambda q: r.run("dsg-1", q, score=101), re_mod.BadScoreError),
        (lambda q: r.run("dsg-1", q, score=True), re_mod.BadScoreError),
        (lambda q: r.run("dsg-1", q, score=1.5), re_mod.BadScoreError),
        (lambda q: r.run("dsg-1", q, run_digest="raw"), re_mod.BadDigestError),
        (lambda q: r.run("dsg-nope", q), re_mod.UnknownRecordError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert r.stats(seq + 1)["rejected"] == len(bad)
    assert r.stats(seq + 1)["runs"] == 0


# 8. score posture math (precedence: brittle > degraded > inconclusive > robust)
def test_score_posture_math():
    r = _re()
    rep = r.score(1)  # empty ledger
    assert rep.posture == "untested" and rep.mean_score is None
    r.design("sys-1", 2)
    rep = r.score(3, "sys-1")  # designed but no runs
    assert rep.posture == "untested"
    r.run("dsg-1", 4, outcome="robust", score=90)
    r.run("dsg-1", 5, outcome="robust", score=80)
    rep = r.score(6, "sys-1")
    assert rep.posture == "robust" and rep.mean_score == 85.0
    r.run("dsg-1", 7, outcome="inconclusive", score=50)
    rep = r.score(8, "sys-1")
    assert rep.posture == "inconclusive"
    r.run("dsg-1", 9, outcome="degraded", score=40)
    rep = r.score(10, "sys-1")
    assert rep.posture == "degraded"
    r.run("dsg-1", 11, outcome="brittle", score=10)
    rep = r.score(12, "sys-1")
    assert rep.posture == "brittle-detected"
    assert rep.verify() and rep.n_runs == 5
    with pytest.raises(re_mod.UnknownSystemError):
        r.score(13, "ghost")


# 9. score whole-ledger aggregation + system scoping
def test_score_aggregation():
    r = _re()
    r.design("sys-a", 1)
    r.design("sys-b", 2)
    r.run("dsg-1", 3, outcome="robust", score=100)
    r.run("dsg-2", 4, outcome="brittle", score=0)
    rep = r.score(5)
    assert rep.system_id == "" and rep.n_systems == 2
    assert rep.n_runs == 2 and rep.posture == "brittle-detected"
    assert rep.mean_score == 50.0
    rep_a = r.score(5, "sys-a")
    assert rep_a.n_systems == 1 and rep_a.posture == "robust"


# 10. seq discipline: rewind bare, malformed seqs, failed mutations consume
def test_seq_discipline():
    r = _re()
    r.design("sys-1", 1)
    with pytest.raises(re_mod.SeqOrderError):
        r.design("sys-2", 1)  # rewind: bare, no rejected row
    assert r.stats(2)["rejected"] == 0
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(re_mod.SeqOrderError):
            r.design("sys-2", bad)
    # view seq shape only (positive int)
    for bad in (0, -1, "2", None, True):
        with pytest.raises(re_mod.SeqOrderError):
            r.score(bad)
    # failed mutation consumes seq: next valid seq is 2 already used
    with pytest.raises(re_mod.BadKindError):
        r.design("sys-2", 2, eval_kind="vibes")
    with pytest.raises(re_mod.SeqOrderError):
        r.design("sys-2", 2)


# 11. view read-purity: same seq twice, no audit rows
def test_view_read_purity():
    r = _re()
    r.design("sys-1", 1)
    r.run("dsg-1", 2, outcome="robust", score=90)
    n_audit = len(r.audit_log(3))
    s1 = r.score(3, "sys-1")
    s2 = r.score(3, "sys-1")
    assert s1.verify() and s2.verify()
    assert len(r.audit_log(3)) == n_audit
    assert r.designs_for("sys-1", 3) == ("dsg-1",)
    assert r.runs_for("sys-1", 3) == ("run-1",)
    assert r.system_ids(3) == ("sys-1",)


# 12. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    r = _re()
    r.design("sys-1", 1, eval_kind="stress")
    r.run("dsg-1", 2, outcome="degraded", score=55)
    rows = r.audit_log(3)
    assert [row["kind"] for row in rows] == [
        "robustness-eval.designed", "robustness-eval.run"]
    for row in rows:
        for key in row["details"]:
            assert key not in re_mod._BANNED_AUDIT_KEYS
    with pytest.raises(re_mod.AuditKindError):
        re_mod.robustness_eval_audit_event("bogus-kind", {})
    with pytest.raises(re_mod.AuditKindError):
        re_mod.robustness_eval_audit_event("designed", {"prompt": "x"})
    with pytest.raises(re_mod.AuditKindError):
        re_mod.robustness_eval_audit_event("designed", "not-a-dict")


# 13. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        r = _re()
        r.design("sys-1", 1, eval_kind="perturbation",
                 robustness_dim="prompt-variants", eval_digest=PIN)
        r.run("dsg-1", 2, outcome="robust", score=77, run_digest=PIN)
        return r

    r1, r2 = build(), build()
    assert r1.design_record("dsg-1", 3).digest == \
        r2.design_record("dsg-1", 3).digest
    assert r1.run_record("run-1", 3).digest == \
        r2.run_record("run-1", 3).digest
    assert r1.score(3, "sys-1").digest == r2.score(3, "sys-1").digest
    import dataclasses
    tampered = dataclasses.replace(r1.run_record("run-1", 3), outcome="brittle")
    assert tampered.verify() is False
    rec = r1.design_record("dsg-1", 3)
    object.__setattr__(rec, "eval_kind", "stress")
    assert rec.verify() is False


# 14. concurrency read smoke + frozen-ness
def test_concurrency_and_frozen():
    r = _re()
    for i in range(10):
        r.design(f"sys-{i}", i + 1)
    results = []

    def worker():
        results.append(r.system_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(ids) == 10 for ids in results)
    d = r.design_record("dsg-1", 100)
    with pytest.raises(Exception):
        d.eval_kind = "stress"  # frozen
    assert d.verify()


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD_PATH)],
        capture_output=True, text=True, cwd=str(MOD_PATH.parent), timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "robustness-eval OK: design, run, score, pins, audit"
    )
