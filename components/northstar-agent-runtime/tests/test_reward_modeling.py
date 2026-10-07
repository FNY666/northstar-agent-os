"""Tests for the reward-modeling governance decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "reward_modeling.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("reward_modeling", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["reward_modeling"] = module
    spec.loader.exec_module(module)
    return module


rm = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert rm.REWARD_MODELING_VERSION == "reward-modeling.v1"
    assert rm.SCHEMA_PIN == "northstar.reward-modeling.v1"
    assert rm.FEEDBACK_KINDS == (
        "preference-pair",
        "demonstration",
        "correction",
        "scalar-rating",
        "ranking",
        "thumbs",
    )
    assert rm.TRAIN_METHODS == (
        "bradley-terry",
        "regression",
        "dpo-style",
        "rlhf-ppo",
        "constitutional",
        "process-supervision",
    )
    assert rm.TRAIN_OUTCOMES == (
        "converged",
        "diverged",
        "not-run",
        "inconclusive",
    )
    assert rm.EVAL_METRICS == (
        "held-out-agreement",
        "calibration",
        "robustness",
        "ood-generalization",
        "human-correlation",
    )
    assert rm.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert set(rm.AUDIT_KINDS) == {
        "collected",
        "trained",
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


# 3. collect roundtrip + verify()
def test_collect_roundtrip_and_verify():
    g = rm.RewardModeling()
    rec = g.collect("ds-a", 1, feedback_kind="preference-pair", feedback_digest=PIN)
    assert rec.collection_id == "col-1"
    assert rec.dataset_id == "ds-a"
    assert rec.feedback_kind == "preference-pair"
    assert rec.feedback_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.reward-modeling.v1"
    fetched = g.collection_record("col-1", 2)
    assert fetched == rec
    assert g.dataset_ids(3) == ("ds-a",)
    assert g.collection_ids(4) == ("col-1",)
    assert g.collections_for("ds-a", 5) == ("col-1",)


# 4. collect bad-input table + seq-burn + rejected rows
def test_collect_bad_inputs_and_seq_burn():
    g = rm.RewardModeling()
    bad = [
        ("", "preference-pair", PIN),
        ("x" * 129, "preference-pair", PIN),
        (None, "preference-pair", PIN),
        ("ok-1", "not-a-kind", PIN),
        ("ok-1", 123, PIN),
        ("ok-1", "preference-pair", "raw-not-a-pin"),
        ("ok-1", "preference-pair", "sha256:" + "zz" * 32),
        ("ok-1", "preference-pair", "sha256:" + "ab" * 16),
        ("ok-1", "preference-pair", ""),
    ]
    seq = 0
    for did, kind, pin in bad:
        seq += 1
        with pytest.raises(rm.RewardModelingError):
            g.collect(did, seq, feedback_kind=kind, feedback_digest=pin)
    assert g.stats(seq + 1)["rejected"] == len(bad)
    assert len(g.audit_log(seq + 2)) == len(bad)
    assert all(row["kind"] == "rejected" for row in g.audit_log(seq + 3))
    # ledger still usable: seq keeps increasing, dataset registered by success
    seq += 1
    rec = g.collect("ok-1", seq + 1, feedback_kind="demonstration", feedback_digest=PIN)
    assert rec.collection_id == "col-1"


# 5. full feedback-kind vocabulary acceptance
def test_all_feedback_kinds_accepted():
    g = rm.RewardModeling()
    for i, kind in enumerate(rm.FEEDBACK_KINDS, start=1):
        rec = g.collect(f"ds-{kind}", i, feedback_kind=kind, feedback_digest=PIN)
        assert rec.collection_id == f"col-{i}"
        assert rec.verify()


# 6. train roundtrip + minted ids + method/outcome vocabulary
def test_train_roundtrip_and_minting():
    g = rm.RewardModeling()
    g.collect("ds-a", 1, feedback_kind="preference-pair", feedback_digest=PIN)
    g.collect("ds-b", 2, feedback_kind="ranking", feedback_digest=PIN)
    seq = 2
    for method in rm.TRAIN_METHODS:
        seq += 1
        trn = g.train("col-1", seq, method=method, outcome="converged",
                      train_digest=PIN2)
        assert trn.training_id == f"trn-{trn.training_id.split('-')[1]}"
        assert trn.verify()
        assert trn.collection_id == "col-1"
        assert trn.dataset_id == "ds-a"
    for outcome in rm.TRAIN_OUTCOMES:
        seq += 1
        trn = g.train("col-2", seq, method="regression", outcome=outcome,
                      train_digest=PIN2)
        assert trn.outcome == outcome
    assert g.training_ids(seq + 1) == tuple(f"trn-{i}" for i in range(1, 11))
    assert len(g.trainings_for("col-1", seq + 2)) == len(rm.TRAIN_METHODS)


# 7. train bad-input table + unknown collection refusal + seq-burn
def test_train_bad_inputs_and_unknown_collection():
    g = rm.RewardModeling()
    g.collect("ds-a", 1, feedback_kind="preference-pair", feedback_digest=PIN)
    bad = [
        ("", "bradley-terry", "converged", PIN),
        ("col-999", "bradley-terry", "converged", PIN),
        ("col-1", "not-a-method", "converged", PIN),
        ("col-1", 42, "converged", PIN),
        ("col-1", "bradley-terry", "not-an-outcome", PIN),
        ("col-1", "bradley-terry", 42, PIN),
        ("col-1", "bradley-terry", "converged", "raw"),
        ("col-1", "bradley-terry", "converged", "sha256:" + "zz" * 32),
        ("col-1", "bradley-terry", "converged", ""),
        (None, "bradley-terry", "converged", PIN),
    ]
    seq = 1
    for cid, method, outcome, pin in bad:
        seq += 1
        with pytest.raises(rm.RewardModelingError):
            g.train(cid, seq, method=method, outcome=outcome, train_digest=pin)
    assert g.stats(seq + 1)["rejected"] == len(bad)


# 8. evaluate roundtrip + minted ids + score boundaries
def test_evaluate_roundtrip_and_score_bounds():
    g = rm.RewardModeling()
    g.collect("ds-a", 1, feedback_kind="preference-pair", feedback_digest=PIN)
    g.train("col-1", 2, method="bradley-terry", outcome="converged",
            train_digest=PIN2)
    seq = 2
    for i, metric in enumerate(rm.EVAL_METRICS, start=1):
        seq += 1
        evl = g.evaluate("trn-1", seq, metric=metric, score=i * 10,
                         eval_digest=PIN3)
        assert evl.evaluation_id == f"evl-{i}"
        assert evl.verify()
        assert evl.training_id == "trn-1"
        assert evl.dataset_id == "ds-a"
        assert evl.metric == metric
    # score boundaries accepted
    seq += 1
    assert g.evaluate("trn-1", seq, metric="calibration", score=0,
                      eval_digest=PIN3).score == 0
    seq += 1
    assert g.evaluate("trn-1", seq, metric="calibration", score=100,
                      eval_digest=PIN3).score == 100
    assert g.evaluation_ids(seq + 1) == tuple(f"evl-{i}" for i in range(1, 8))
    assert len(g.evaluations_for("trn-1", seq + 2)) == 7


# 9. evaluate bad-input table + unknown training refusal
def test_evaluate_bad_inputs_and_unknown_training():
    g = rm.RewardModeling()
    g.collect("ds-a", 1, feedback_kind="preference-pair", feedback_digest=PIN)
    g.train("col-1", 2, method="bradley-terry", outcome="converged",
            train_digest=PIN2)
    bad = [
        ("", "held-out-agreement", 50, PIN),
        ("trn-999", "held-out-agreement", 50, PIN),
        ("trn-1", "not-a-metric", 50, PIN),
        ("trn-1", 42, 50, PIN),
        ("trn-1", "held-out-agreement", -1, PIN),
        ("trn-1", "held-out-agreement", 101, PIN),
        ("trn-1", "held-out-agreement", True, PIN),
        ("trn-1", "held-out-agreement", 1.5, PIN),
        ("trn-1", "held-out-agreement", None, PIN),
        ("trn-1", "held-out-agreement", 50, "raw"),
        ("trn-1", "held-out-agreement", 50, ""),
        (None, "held-out-agreement", 50, PIN),
    ]
    seq = 2
    for tid, metric, score, pin in bad:
        seq += 1
        with pytest.raises(rm.RewardModelingError):
            g.evaluate(tid, seq, metric=metric, score=score, eval_digest=pin)
    assert g.stats(seq + 1)["rejected"] == len(bad)


# 10. retire terminality + id non-recycling + post-retire refusals
def test_retire_terminality():
    g = rm.RewardModeling()
    g.collect("ds-a", 1, feedback_kind="preference-pair", feedback_digest=PIN)
    g.collect("ds-b", 2, feedback_kind="ranking", feedback_digest=PIN)
    trn = g.train("col-1", 3, method="bradley-terry", outcome="converged",
                  train_digest=PIN2)
    # bad reason on a known live dataset burns a seq
    with pytest.raises(rm.BadReasonError):
        g.retire("ds-b", 4, reason="vibes")
    rec = g.retire("ds-a", 5, reason="decommissioned")
    assert rec.verify()
    assert g.retired_ids(6) == ("ds-a",)
    # post-retire mutations all refused, fail-closed
    with pytest.raises(rm.RetiredDatasetError):
        g.collect("ds-a", 7, feedback_kind="ranking", feedback_digest=PIN)
    with pytest.raises(rm.RetiredDatasetError):
        g.train("col-1", 8, method="regression", outcome="diverged",
                train_digest=PIN2)
    with pytest.raises(rm.RetiredDatasetError):
        g.evaluate(trn.training_id, 9, metric="calibration", score=50,
                   eval_digest=PIN3)
    with pytest.raises(rm.RetiredDatasetError):
        g.retire("ds-a", 10, reason="manual")
    # reads still work after retire
    assert g.collection_record("col-1", 11).dataset_id == "ds-a"
    rep = g.report("ds-a", 12)
    assert rep.n_collections == 1
    assert g.stats(13)["rejected"] == 5


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation burns
def test_seq_discipline():
    g = rm.RewardModeling()
    g.collect("ds-a", 1, feedback_kind="preference-pair", feedback_digest=PIN)
    # rewind raises bare without consuming / without a rejected row
    with pytest.raises(rm.SeqOrderError):
        g.collect("ds-b", 1, feedback_kind="ranking", feedback_digest=PIN)
    with pytest.raises(rm.SeqOrderError):
        g.train("col-1", 1, method="regression", outcome="converged",
                train_digest=PIN2)
    assert g.stats(2)["rejected"] == 0
    # malformed seqs on reads and mutations
    for bad in (True, "1", 1.5, None, 0, -3):
        with pytest.raises(rm.SeqOrderError):
            g.dataset_ids(bad)
        with pytest.raises(rm.SeqOrderError):
            g.collect("ds-b", bad, feedback_kind="ranking", feedback_digest=PIN)
    # failed mutation consumes its seq
    with pytest.raises(rm.BadFeedbackKindError):
        g.collect("ds-b", 2, feedback_kind="vibes", feedback_digest=PIN)
    assert g.stats(3)["rejected"] == 1
    # ledger continues at strictly increasing seqs only
    rec = g.collect("ds-b", 3, feedback_kind="ranking", feedback_digest=PIN)
    assert rec.collection_id == "col-2"


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    g = rm.RewardModeling()
    g.collect("ds-a", 1, feedback_kind="preference-pair", feedback_digest=PIN)
    g.train("col-1", 2, method="bradley-terry", outcome="converged",
            train_digest=PIN2)
    g.evaluate("trn-1", 3, metric="held-out-agreement", score=87,
               eval_digest=PIN3)
    g.retire("ds-a", 4, reason="manual")
    log = g.audit_log(5)
    kinds = [row["kind"] for row in log]
    assert kinds == ["collected", "trained", "evaluated", "retired"]
    for row in log:
        assert row["schema"] == "audit.ndjson/1"
        assert row["seq"] >= 1
    # pinned vocabulary values remain emittable as declared data
    trn_row = log[1]
    assert trn_row["details"]["method"] == "bradley-terry"
    assert trn_row["details"]["outcome"] == "converged"
    evl_row = log[2]
    assert evl_row["details"]["metric"] == "held-out-agreement"
    # raw material keys are banned at the builder level
    for banned in ("reward", "policy", "trajectory", "gradient", "evidence",
                   "feedback", "preference", "score", "weights", "loss"):
        with pytest.raises(rm.AuditKindError):
            rm.reward_modeling_audit_event("collected", 9, **{banned: "x"})
    # bad kind
    with pytest.raises(rm.AuditKindError):
        rm.reward_modeling_audit_event("modeled", 9)
    # builder seq must be non-negative int
    with pytest.raises(rm.SeqOrderError):
        rm.reward_modeling_audit_event("collected", -1)
    # one failure booked a rejected row
    with pytest.raises(rm.BadFeedbackKindError):
        g.collect("ds-b", 6, feedback_kind="vibes", feedback_digest=PIN)
    log2 = g.audit_log(7)
    assert log2[-1]["kind"] == "rejected"
    assert log2[-1]["details"]["method"] == "collect"
    assert log2[-1]["details"]["error"] == "BadFeedbackKindError"


# 13. report read purity + posture math + integrity flip on tamper
def test_report_read_purity_and_integrity():
    g = rm.RewardModeling()
    g.collect("ds-a", 1, feedback_kind="preference-pair", feedback_digest=PIN)
    rep = g.report("ds-a", 2)
    assert rep.posture == "collected"
    assert rep.n_collections == 1
    assert rep.n_trainings == 0
    g.train("col-1", 3, method="bradley-terry", outcome="converged",
            train_digest=PIN2)
    rep = g.report("ds-a", 4)
    assert rep.posture == "trained"
    assert rep.n_trainings == 1
    g.evaluate("trn-1", 5, metric="held-out-agreement", score=87,
               eval_digest=PIN3)
    rep = g.report("ds-a", 6)
    assert rep.posture == "evaluated"
    assert rep.n_evaluations == 1
    assert rep.integrity_ok is True
    assert rep.verify()
    # same-seq reads twice: pure, no audit rows, no consumption
    before = len(g.audit_log(7))
    assert g.report("ds-a", 8) == g.report("ds-a", 8)
    assert len(g.audit_log(8)) == before
    # tamper breaks verify() on the record; integrity_ok flips as data
    rec = g.collection_record("col-1", 9)
    object.__setattr__(rec, "feedback_kind", "minted-money")
    assert not rec.verify()
    rep2 = g.report("ds-a", 10)
    assert rep2.integrity_ok is False
    assert rep2.verify()  # tamper reported, never raised
    # unknown dataset is refused
    with pytest.raises(rm.UnknownDatasetError):
        g.report("ds-ghost", 11)


# 14. cross-instance determinism + frozen-ness + read thread smoke
def test_determinism_frozen_and_threads():
    g1 = rm.RewardModeling()
    g2 = rm.RewardModeling()
    for i, g in enumerate((g1, g2), start=1):
        g.collect("ds-a", i, feedback_kind="preference-pair", feedback_digest=PIN)
    assert g1.collection_record("col-1", 3).digest == g2.collection_record("col-1", 3).digest
    # records are frozen
    rec = g1.collection_record("col-1", 4)
    with pytest.raises(Exception):
        rec.feedback_kind = "x"  # type: ignore
    # 8 threads of pure reads with the same seq
    errors = []

    def reader():
        try:
            for _ in range(50):
                g1.report("ds-a", 5)
                g1.collection_record("col-1", 5)
                g1.stats(5)
                g1.audit_log(5)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert "reward-modeling OK: collect, train, evaluate, retire, pins, audit" in proc.stdout
