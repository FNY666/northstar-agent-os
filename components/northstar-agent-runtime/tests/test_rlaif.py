"""Targeted tests for the RLAIF ledger (rlaif.py)."""

import ast
import hashlib
import os
import subprocess
import sys

import pytest

from rlaif import (
    RLAIF,
    RLAIFError,
    RLAIF_SCHEMA,
    RLAIF_VERSION,
    AuditKindError,
    BadDigestError,
    BadIssueError,
    BadSampleError,
    BadScoreError,
    BadSourceError,
    BadVerdictError,
    BadWinnerError,
    DuplicatePreferenceError,
    DuplicateSampleError,
    InconsistentVerdictError,
    NoTrainingSignalError,
    SelfPairError,
    SeqOrderError,
    UnknownSampleError,
    rlaif_audit_event,
)


def _module_path():
    return os.path.join(os.path.dirname(__file__), "..", "rlaif.py")


def _d(tag):
    return "sha256:" + hashlib.sha256(tag.encode("utf-8")).hexdigest()


def _ledger():
    return RLAIF()


def _samples(r, ids=("a", "b")):
    seq = 0
    for sid in ids:
        seq += 1
        r.sample(sid, _d("p-" + sid), _d("o-" + sid), seq)
    return seq


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert RLAIF_VERSION == "rlaif.v1"
    assert RLAIF_SCHEMA == "northstar.rlaif.v1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "fractions",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# sample
# ---------------------------------------------------------------------------


def test_sample_roundtrip_and_digest():
    r = _ledger()
    rec = r.sample("s1", _d("p"), _d("o"), 1)
    assert rec.sample_id == "s1"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("s1", _d("p"), _d("o"))
    assert not rec.verify("s1", _d("p"), _d("other"))
    assert r.sample_record("s1", 99) is rec
    assert r.sample_ids(2) == ("s1",)
    stats = r.stats(3)
    assert stats["samples"] == 1
    assert stats["last_seq"] == 1


def test_sample_bad_inputs_burn_seq():
    r = _ledger()
    start_rows = len(r.audit_log(0))
    for kwargs in (
        {"sample_id": "", "prompt_digest": _d("p"), "output_digest": _d("o")},
        {"sample_id": "a b", "prompt_digest": _d("p"),
         "output_digest": _d("o")},
        {"sample_id": "x" * 300, "prompt_digest": _d("p"),
         "output_digest": _d("o")},
        {"sample_id": 123, "prompt_digest": _d("p"), "output_digest": _d("o")},
        {"sample_id": True, "prompt_digest": _d("p"), "output_digest": _d("o")},
        {"sample_id": "s", "prompt_digest": "raw-text", "output_digest": _d("o")},
        {"sample_id": "s", "prompt_digest": "", "output_digest": _d("o")},
        {"sample_id": "s", "prompt_digest": None, "output_digest": _d("o")},
    ):
        before = r.stats(0)["last_seq"]
        with pytest.raises(RLAIFError):
            r.sample(seq=before + 1, **kwargs)
        # failed mutation consumed its seq and booked a rejected row
        assert r.stats(0)["last_seq"] == before + 1
    assert len(r.audit_log(0)) == start_rows + 8
    assert all(row["kind"] == "rejected" for row in r.audit_log(0)[start_rows:])
    # duplicate id refused
    r.sample("dup", _d("p"), _d("o"), 100)
    with pytest.raises(DuplicateSampleError):
        r.sample("dup", _d("p2"), _d("o2"), 101)


# ---------------------------------------------------------------------------
# critique
# ---------------------------------------------------------------------------


def test_critique_roundtrip_and_digest():
    r = _ledger()
    _samples(r)
    rec = r.critique("a", 3, issues=("formatting", "hallucination"),
                     feedback_digest=_d("fb"))
    assert rec.critique_id == "crit-1"
    assert rec.issues == ("formatting", "hallucination")  # sorted
    assert rec.verdict == "needs-revision"
    assert rec.verify("a", ("formatting", "hallucination"), "needs-revision")
    assert not rec.verify("a", ("formatting",), "needs-revision")
    # dedup + unsorted input normalized
    rec2 = r.critique("b", 4, issues=("off-task", "off-task", "incomplete"),
                      verdict="reject")
    assert rec2.critique_id == "crit-2"
    assert rec2.issues == ("incomplete", "off-task")
    # empty issues requires accept
    rec3 = r.critique("a", 5, issues=(), verdict="accept")
    assert rec3.verdict == "accept"
    assert r.critique_record("crit-1", 9) is rec


def test_critique_bad_inputs():
    r = _ledger()
    _samples(r, ids=("a",))
    with pytest.raises(UnknownSampleError):
        r.critique("ghost", 3, issues=("formatting",))
    with pytest.raises(BadIssueError):
        r.critique("a", 4, issues=("made-up-issue",))
    with pytest.raises(BadIssueError):
        r.critique("a", 5, issues="formatting")  # bare string refused
    with pytest.raises(BadDigestError):
        r.critique("a", 6, issues=(), verdict="accept",
                   feedback_digest="not-a-digest")
    with pytest.raises(BadVerdictError):
        r.critique("a", 7, issues=(), verdict="maybe")
    # consistency rule: empty issues + needs-revision refused
    with pytest.raises(InconsistentVerdictError):
        r.critique("a", 8, issues=())
    # consistency rule: non-empty issues + accept refused
    with pytest.raises(InconsistentVerdictError):
        r.critique("a", 9, issues=("formatting",), verdict="accept")


# ---------------------------------------------------------------------------
# prefer
# ---------------------------------------------------------------------------


def test_prefer_roundtrip_and_digest():
    r = _ledger()
    _samples(r)
    rec = r.prefer("a", "b", "a", 3)
    assert rec.preference_id == "pref-1"
    assert rec.winner == "a"
    assert rec.verify("a", "b", "a")
    assert not rec.verify("a", "b", "b")
    # tie on a fresh pair
    r.sample("c", _d("pc"), _d("oc"), 4)
    rec2 = r.prefer("a", "c", "tie", 5)
    assert rec2.winner == "tie"
    assert r.preference_record("pref-1", 9) is rec
    assert r.stats(9)["preferences"] == 2


def test_prefer_bad_inputs():
    r = _ledger()
    _samples(r, ids=("a", "b"))
    with pytest.raises(SelfPairError):
        r.prefer("a", "a", "a", 3)
    with pytest.raises(UnknownSampleError):
        r.prefer("a", "ghost", "a", 4)
    with pytest.raises(UnknownSampleError):
        r.prefer("ghost", "a", "b", 5)
    with pytest.raises(BadWinnerError):
        r.prefer("a", "b", "neither", 6)
    r.prefer("a", "b", "a", 7)
    with pytest.raises(DuplicatePreferenceError):
        r.prefer("b", "a", "b", 8)  # same unordered pair, flipped order
    with pytest.raises(DuplicatePreferenceError):
        r.prefer("a", "b", "tie", 9)


# ---------------------------------------------------------------------------
# reward
# ---------------------------------------------------------------------------


def test_reward_roundtrip_and_digest():
    r = _ledger()
    _samples(r, ids=("a",))
    rec = r.reward("a", 0.75, 2)
    assert rec.reward_id == "rew-1"
    assert rec.score == 0.75
    assert rec.source == "ai-judge"
    assert rec.verify("a", 0.75, "ai-judge")
    assert not rec.verify("a", 0.75, "heuristic")
    rec2 = r.reward("a", 1, 3, source="preference-model")  # int accepted
    assert rec2.score == 1.0
    assert r.latest_reward_id("a", 9) == "rew-2"
    assert r.reward_record("rew-1", 9) is rec


def test_reward_bad_inputs():
    r = _ledger()
    _samples(r, ids=("a",))
    bad_scores = (True, float("nan"), float("inf"), float("-inf"),
                  1.5, -1.5, "0.5", None, [0.1])
    seq = 2
    for score in bad_scores:
        seq += 1
        with pytest.raises(BadScoreError):
            r.reward("a", score, seq)
    # seq burned on each failed mutation
    assert r.stats(0)["last_seq"] == seq
    seq += 1
    with pytest.raises(BadSourceError):
        r.reward("a", 0.1, seq, source="human")
    with pytest.raises(UnknownSampleError):
        r.reward("ghost", 0.1, seq + 1)
    # boundary scores accepted
    r.reward("a", -1.0, seq + 2)
    r.reward("a", 1.0, seq + 3)


# ---------------------------------------------------------------------------
# train
# ---------------------------------------------------------------------------


def test_train_roundtrip_and_agreement():
    r = _ledger()
    seq = _samples(r, ids=("a", "b", "c"))
    seq += 1
    r.prefer("a", "b", "a", seq)
    seq += 1
    r.prefer("a", "c", "b", seq)  # "b" = the second sample (c) wins
    seq += 1
    r.reward("a", 0.8, seq)
    seq += 1
    r.reward("b", -0.2, seq)
    seq += 1
    r.reward("c", 0.9, seq)
    seq += 1
    rec = r.train(seq)
    assert rec.step_id == "step-1"
    assert rec.pairs_scored == 2
    # a>b: 0.8 > -0.2 match; c>a: 0.9 > 0.8 match -> 2/2, reduced to 1/1
    assert rec.agreement == "1/1"
    # mean margin: ((0.8 - -0.2) + (0.9 - 0.8)) / 2 = 0.55
    assert rec.mean_margin == "0.550000"
    assert rec.verify(2, "1/1", "0.550000")
    assert not rec.verify(2, "1/2", "0.550000")
    assert r.training_record("step-1", 99) is rec
    # ties excluded from agreement
    seq += 1
    r.sample("d", _d("pd"), _d("od"), seq)
    seq += 1
    r.prefer("b", "d", "tie", seq)
    seq += 1
    rec2 = r.train(seq)
    assert rec2.pairs_scored == 2
    assert rec2.step_id == "step-2"


def test_train_no_signal():
    r = _ledger()
    seq = _samples(r, ids=("a", "b"))
    seq += 1
    with pytest.raises(NoTrainingSignalError):
        r.train(seq)  # no preferences at all
    seq += 1
    r.prefer("a", "b", "a", seq)
    seq += 1
    with pytest.raises(NoTrainingSignalError):
        r.train(seq)  # preferences but no rewards -> no scored pairs
    seq += 1
    r.reward("a", 0.1, seq)
    seq += 1
    with pytest.raises(NoTrainingSignalError):
        r.train(seq)  # only one side scored
    # tie-only preferences never count as signal
    r2 = _ledger()
    s2 = _samples(r2, ids=("x", "y"))
    s2 += 1
    r2.prefer("x", "y", "tie", s2)
    s2 += 1
    r2.reward("x", 0.5, s2)
    s2 += 1
    r2.reward("y", -0.5, s2)
    s2 += 1
    with pytest.raises(NoTrainingSignalError):
        r2.train(s2)


# ---------------------------------------------------------------------------
# seq discipline, audit, main
# ---------------------------------------------------------------------------


def test_seq_discipline():
    r = _ledger()
    r.sample("s", _d("p"), _d("o"), 1)
    # rewind raises bare without consuming
    with pytest.raises(SeqOrderError):
        r.sample("t", _d("p"), _d("o"), 1)
    assert r.stats(0)["last_seq"] == 1
    for bad in (True, -1, "2", 1.5, None):
        with pytest.raises(SeqOrderError):
            r.sample("t", _d("p"), _d("o"), bad)
    # views validate shape only, consume nothing
    assert r.sample_record("s", 1) is not None
    assert r.sample_record("missing", 1) is None
    assert r.stats(999)["last_seq"] == 1
    assert r.audit_log(5) != ()


def test_audit_shapes_and_leak_ban():
    r = _ledger()
    seq = _samples(r, ids=("a", "b"))
    seq += 1
    r.critique("a", seq, issues=("formatting",),
               feedback_digest=_d("fb"))
    seq += 1
    r.prefer("a", "b", "b", seq)
    seq += 1
    r.reward("a", 0.1, seq)
    seq += 1
    r.reward("b", 0.9, seq)
    seq += 1
    r.train(seq)
    rows = r.audit_log(99)
    kinds = [row["kind"] for row in rows]
    assert kinds == ["sample-declared", "sample-declared", "critiqued",
                    "preference-labeled", "reward-booked", "reward-booked",
                    "trained"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "rlaif.v1"
        assert isinstance(row["seq"], int)
        banned = {"prompt", "output", "feedback", "text", "raw", "payload",
                  "value", "data", "variables", "scores"}
        assert not banned.intersection(row["detail"].keys())
    # audit builder rejects unknown kinds and banned keys
    with pytest.raises(AuditKindError):
        rlaif_audit_event("nope", {}, 1)
    with pytest.raises(AuditKindError):
        rlaif_audit_event("critiqued", {"feedback": "raw"}, 1)
    ev = rlaif_audit_event("trained", {"step_id": "step-1"}, 7)
    assert ev["kind"] == "trained" and ev["seq"] == 7


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, _module_path()],
        capture_output=True, text=True, cwd="/tmp", timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "rlaif OK: sample, critique, prefer, reward, train, pins, audit")
