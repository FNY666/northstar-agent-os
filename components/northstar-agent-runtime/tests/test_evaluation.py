"""Tests for the evaluation governance ledger (Simulated)."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "evaluation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("evaluation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["evaluation"] = module
    spec.loader.exec_module(module)
    return module


ev = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ev.EVALUATION_VERSION == "evaluation.v1"
    assert ev.SCHEMA_PIN == "northstar.evaluation.v1"
    assert ev.TASK_DOMAINS == (
        "reasoning",
        "coding",
        "tool-use",
        "safety",
        "alignment",
        "deception",
        "multimodal",
        "long-context",
    )
    assert ev.METHODOLOGIES == (
        "held-out-suite",
        "human-grading",
        "model-grading",
        "behavioral-probe",
        "red-team-adversarial",
        "self-report",
    )
    assert ev.RUN_KINDS == ("baseline", "elicitation", "ablated", "replicated")
    assert ev.RETIRE_REASONS == (
        "manual",
        "suite-superseded",
        "protocol-complete",
        "invalidated",
    )
    assert ev.VERDICTS == ("unevaluated", "pass", "marginal", "fail")
    assert ev.AUDIT_KINDS == ("designed", "run_recorded", "retired", "rejected")
    assert ev.PASS_MARK == 70
    assert ev.FAIL_MARK == 50


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
        "ast",
        "pathlib",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed
    assert ev.Evaluation.stdlib_only()


# 3. design() roundtrip + record verify
def test_design_roundtrip():
    e = ev.Evaluation()
    rec = e.design(
        "EV-1",
        "safety",
        1,
        methodology="human-grading",
        design_digest=PIN,
    )
    assert rec.design_id == "EV-1"
    assert rec.task_domain == "safety"
    assert rec.methodology == "human-grading"
    assert rec.verify()
    assert e.design_record("EV-1", 0).verify()
    rows = e.audit_log(0)
    assert rows[-1]["kind"] == "designed"
    assert rows[-1]["details"]["design_id"] == "EV-1"
    assert rows[-1]["details"]["methodology"] == "human-grading"


# 4. design bad-input table + seq-burn + rejected rows
def test_design_bad_inputs_and_seq_burn():
    e = ev.Evaluation()
    e.design("EV-1", "reasoning", 1)
    seq = 2
    with pytest.raises(ev.DuplicateDesignError):
        e.design("EV-1", "reasoning", seq)
    seq += 1
    with pytest.raises(ev.BadIdError):
        e.design("", "reasoning", seq)
    seq += 1
    with pytest.raises(ev.BadDomainError):
        e.design("EV-2", "astrology", seq)
    seq += 1
    with pytest.raises(ev.BadMethodologyError):
        e.design("EV-2", "reasoning", seq, methodology="vibes")
    seq += 1
    with pytest.raises(ev.BadDigestError):
        e.design("EV-2", "reasoning", seq, design_digest="nope")
    # every failed mutation consumed its seq and booked a rejected row
    assert e.stats(0)["seq"] == seq
    rows = e.audit_log(0)
    assert len([r for r in rows if r["kind"] == "rejected"]) == 5
    # seq is burned: reusing it rewinds bare with no new row
    with pytest.raises(ev.SeqOrderError):
        e.design("EV-3", "reasoning", seq)
    assert len([r for r in e.audit_log(0) if r["kind"] == "rejected"]) == 5


# 5. retired ids never recycled
def test_duplicate_and_retired_id_never_recycled():
    e = ev.Evaluation()
    e.design("EV-1", "coding", 1)
    e.retire("EV-1", 2, reason="protocol-complete")
    assert "EV-1" in e.retired_ids(0)
    with pytest.raises(ev.RetiredDesignError):
        e.design("EV-1", "coding", 3)
    with pytest.raises(ev.RetiredDesignError):
        e.retire("EV-1", 4)
    with pytest.raises(ev.RetiredDesignError):
        e.run("EV-1", 5, run_kind="baseline", score=50)
    assert e.stats(0)["designs"] == 1


# 6. full domain x methodology vocabulary acceptance
def test_full_domain_and_methodology_vocabulary():
    e = ev.Evaluation()
    seq = 0
    i = 0
    for domain in ev.TASK_DOMAINS:
        for methodology in ev.METHODOLOGIES:
            seq += 1
            rec = e.design(f"EV-{i}", domain, seq, methodology=methodology)
            assert rec.verify()
            assert rec.task_domain == domain
            assert rec.methodology == methodology
            i += 1
    assert e.stats(0)["designs"] == len(ev.TASK_DOMAINS) * len(ev.METHODOLOGIES)


# 7. run roundtrip + minted ids + score normalization
def test_run_roundtrip_and_minting():
    e = ev.Evaluation()
    e.design("EV-1", "alignment", 1, design_digest=PIN)
    r = e.run("EV-1", 2, run_kind="baseline", score=82, run_digest=PIN2)
    assert r.run_id == "run-1"
    assert r.design_id == "EV-1"
    assert r.run_kind == "baseline"
    assert r.score == 82 and r.score_scale == 100
    assert r.normalized == 82
    assert r.verify()
    r2 = e.run("EV-1", 3, run_kind="elicitation", score=9, score_scale=10)
    assert r2.run_id == "run-2"
    assert r2.normalized == 90
    assert r2.verify()
    assert e.run_record("run-1", 0).verify()
    runs = e.runs_for("EV-1", 0)
    assert [x.run_id for x in runs] == ["run-1", "run-2"]
    rows = e.audit_log(0)
    assert rows[-1]["kind"] == "run_recorded"
    assert rows[-1]["details"]["run_id"] == "run-2"
    assert rows[-1]["details"]["normalized"] == 90


# 8. run bad-input table + seq-burn
def test_run_bad_inputs_and_seq_burn():
    e = ev.Evaluation()
    e.design("EV-1", "deception", 1)
    seq = 2
    with pytest.raises(ev.UnknownDesignError):
        e.run("EV-NOPE", seq, run_kind="baseline", score=50)
    seq += 1
    with pytest.raises(ev.BadRunKindError):
        e.run("EV-1", seq, run_kind="hallucination", score=50)
    seq += 1
    with pytest.raises(ev.BadScoreError):
        e.run("EV-1", seq, run_kind="baseline", score=101)
    seq += 1
    with pytest.raises(ev.BadScoreError):
        e.run("EV-1", seq, run_kind="baseline", score=-1)
    seq += 1
    with pytest.raises(ev.BadScoreError):
        e.run("EV-1", seq, run_kind="baseline", score=True)
    seq += 1
    with pytest.raises(ev.BadScoreError):
        e.run("EV-1", seq, run_kind="baseline", score=50.5)
    seq += 1
    with pytest.raises(ev.BadScaleError):
        e.run("EV-1", seq, run_kind="baseline", score=1, score_scale=0)
    seq += 1
    with pytest.raises(ev.BadDigestError):
        e.run("EV-1", seq, run_kind="baseline", score=50, run_digest="raw")
    assert e.stats(0)["seq"] == seq
    rows = e.audit_log(0)
    assert len([r for r in rows if r["kind"] == "rejected"]) == 8
    assert e.stats(0)["runs"] == 0


# 9. full run-kind vocabulary + score boundaries
def test_full_run_kind_vocabulary_and_boundaries():
    e = ev.Evaluation()
    e.design("EV-1", "tool-use", 1)
    seq = 1
    for i, kind in enumerate(ev.RUN_KINDS):
        seq += 1
        rec = e.run("EV-1", seq, run_kind=kind, score=i * 25)
        assert rec.run_kind == kind and rec.verify()
    # boundaries: 0 and exactly scale accepted
    seq += 1
    lo = e.run("EV-1", seq, run_kind="baseline", score=0)
    assert lo.normalized == 0
    seq += 1
    hi = e.run("EV-1", seq, run_kind="baseline", score=100)
    assert hi.normalized == 100
    assert e.stats(0)["runs"] == len(ev.RUN_KINDS) + 2


# 10. analyze verdict math + read purity
def test_analyze_verdict_math():
    e = ev.Evaluation()
    e.design("EV-A", "safety", 1)
    assert e.analyze("EV-A", 0).verdict == "unevaluated"
    e.design("EV-P", "safety", 2)
    e.run("EV-P", 3, run_kind="baseline", score=70)
    e.run("EV-P", 4, run_kind="replicated", score=100)
    rep = e.analyze("EV-P", 0)
    assert rep.n_runs == 2 and rep.verdict == "pass"
    assert rep.mean_normalized == 85 and rep.min_normalized == 70
    assert rep.verify() and rep.integrity_ok is True
    e.design("EV-M", "safety", 5)
    e.run("EV-M", 6, run_kind="baseline", score=69)
    assert e.analyze("EV-M", 0).verdict == "marginal"
    e.design("EV-F", "safety", 7)
    e.run("EV-F", 8, run_kind="baseline", score=95)
    e.run("EV-F", 9, run_kind="elicitation", score=49)
    rep_f = e.analyze("EV-F", 0)
    assert rep_f.verdict == "fail"
    assert rep_f.mean_normalized == 72 and rep_f.min_normalized == 49
    # analyze is a pure read: same seq twice, no audit rows, no seq burn
    rows_before = len(e.audit_log(0))
    a1 = e.analyze("EV-P", 10)
    a2 = e.analyze("EV-P", 10)
    assert a1.digest == a2.digest
    assert len(e.audit_log(0)) == rows_before
    assert e.stats(0)["seq"] == 9
    with pytest.raises(ev.UnknownDesignError):
        e.analyze("EV-NOPE", 10)


# 11. retire terminality + reads still work
def test_retire_terminality():
    e = ev.Evaluation()
    e.design("EV-1", "multimodal", 1, design_digest=PIN)
    e.run("EV-1", 2, run_kind="baseline", score=88)
    with pytest.raises(ev.BadReasonError):
        e.retire("EV-1", 3, reason="gave-up")
    r = e.retire("EV-1", 4, reason="suite-superseded")
    assert r.verify() and r.reason == "suite-superseded"
    with pytest.raises(ev.RetiredDesignError):
        e.retire("EV-1", 5)
    with pytest.raises(ev.RetiredDesignError):
        e.run("EV-1", 6, run_kind="baseline", score=10)
    # reads still work after retirement
    rep = e.analyze("EV-1", 0)
    assert rep.verdict == "pass" and rep.verify()
    assert e.design_record("EV-1", 0).verify()
    assert len(e.runs_for("EV-1", 0)) == 1
    assert e.stats(0)["live"] == 0 and e.stats(0)["retired"] == 1


# 12. seq discipline: rewind bare, malformed seqs, no burn on reads
def test_seq_discipline():
    e = ev.Evaluation()
    e.design("EV-1", "reasoning", 1)
    before = len([r for r in e.audit_log(0) if r["kind"] == "rejected"])
    with pytest.raises(ev.SeqOrderError):
        e.design("EV-2", "reasoning", 1)
    assert len([r for r in e.audit_log(0) if r["kind"] == "rejected"]) == before
    for bad in (True, "2", 2.0, None, -1, 0):
        with pytest.raises(ev.SeqOrderError):
            e.design("EV-2", "reasoning", bad)
    assert len([r for r in e.audit_log(0) if r["kind"] == "rejected"]) == before
    # view seqs are shape-validated only, never consumed
    with pytest.raises(ev.SeqOrderError):
        e.analyze("EV-1", -1)
    a1 = e.analyze("EV-1", 1)
    a2 = e.analyze("EV-1", 1)
    assert a1.digest == a2.digest
    assert e.stats(0)["seq"] == 1


# 13. view read-purity
def test_view_read_purity():
    e = ev.Evaluation()
    e.design("EV-1", "long-context", 1)
    e.run("EV-1", 2, run_kind="ablated", score=60)
    e.retire("EV-1", 3, reason="manual")
    rows_before = len(e.audit_log(0))
    for _ in range(3):
        e.analyze("EV-1", 5)
        e.design_record("EV-1", 5)
        e.run_record("run-1", 5)
        e.runs_for("EV-1", 5)
        e.design_ids(5)
        e.run_ids(5)
        e.live_ids(5)
        e.retired_ids(5)
        e.stats(5)
    assert len(e.audit_log(0)) == rows_before
    assert e.stats(0)["seq"] == 3


# 14. audit shapes + leak ban + bad kind
def test_audit_shapes_leak_ban_bad_kind():
    e = ev.Evaluation()
    e.design("EV-1", "coding", 1)
    e.run("EV-1", 2, run_kind="baseline", score=77)
    e.retire("EV-1", 3, reason="invalidated")
    rows = e.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["designed", "run_recorded", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert isinstance(r["seq"], int) and r["seq"] >= 0
    # raw eval material is banned at the builder level
    for bad_key in ("question", "transcript", "prompt", "weights", "solution"):
        with pytest.raises(ev.AuditKindError):
            ev.evaluation_audit_event("designed", 1, **{bad_key: "raw-material"})
    # pinned declared-data keys remain emittable
    row = ev.evaluation_audit_event(
        "run_recorded", 1, run_kind="baseline", normalized=77
    )
    assert row["details"]["normalized"] == 77
    with pytest.raises(ev.AuditKindError):
        ev.evaluation_audit_event("pwned", 1)
    with pytest.raises(ev.SeqOrderError):
        ev.evaluation_audit_event("designed", -1)


# 15. determinism + tamper + frozen-ness + thread smoke + main()
def test_determinism_tamper_frozen_and_main():
    a = ev.Evaluation()
    b = ev.Evaluation()
    a.design("EV-1", "safety", 1, design_digest=PIN)
    b.design("EV-1", "safety", 1, design_digest=PIN)
    a.run("EV-1", 2, run_kind="baseline", score=81)
    b.run("EV-1", 2, run_kind="baseline", score=81)
    assert a.run_record("run-1", 0).digest == b.run_record("run-1", 0).digest
    # tamper breaks verify() as data
    rec = a.run_record("run-1", 0)
    object.__setattr__(rec, "normalized", 0)
    assert rec.verify() is False
    rep = a.analyze("EV-1", 0)
    assert rep.integrity_ok is False
    assert rep.verdict == "fail"  # tampered normalized score feeds the verdict
    assert rep.verify() is True
    # frozen-ness
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.normalized = 81  # noqa: B018
    # 8-thread read smoke
    errors = []

    def _read():
        try:
            for _ in range(50):
                a.analyze("EV-1", 0)
                a.run_record("run-1", 0)
                a.stats(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_read) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors
    # main() subprocess check
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "evaluation OK: design, run, analyze, pins, audit" in proc.stdout
