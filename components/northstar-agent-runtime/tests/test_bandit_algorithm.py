"""Tests for bandit_algorithm: multi-armed bandit decision ledger."""

import ast
import subprocess
import sys

import pytest

import bandit_algorithm as ba
from bandit_algorithm import BanditAlgorithm


def _module_path():
    return ba.__file__


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert ba.BANDIT_ALGORITHM_VERSION == "bandit-algorithm.v1"
    assert ba.BANDIT_ALGORITHM_SCHEMA == "northstar.bandit-algorithm.v1"
    assert ba.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "math", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# arm
# ---------------------------------------------------------------------------


def test_arm_roundtrip_and_digest():
    b = BanditAlgorithm()
    rec = b.arm("variant-a", 1)
    assert rec.arm_id == "variant-a"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("variant-a")
    assert not rec.verify("variant-b")
    assert b.arm_record("variant-a") == rec
    assert b.arm_record("nope") is None
    assert b.arm_ids() == ("variant-a",)


def test_arm_duplicate_and_bad_inputs_consume_seq_and_audit_rejected():
    b = BanditAlgorithm()
    b.arm("a1", 1)
    with pytest.raises(ba.DuplicateArmError):
        b.arm("a1", 2)
    with pytest.raises(ba.BadArmError):
        b.arm("", 3)
    with pytest.raises(ba.BadArmError):
        b.arm("has space", 4)
    with pytest.raises(ba.BadArmError):
        b.arm("x" * 257, 5)
    with pytest.raises(ba.BadArmError):
        b.arm(123, 6)
    rejected = [r for r in b.audit_log() if r["kind"] == ba.KIND_REJECTED]
    assert len(rejected) == 5
    assert b.arm_ids() == ("a1",)


def test_arm_malformed_seq_rewind_raises_bare_without_consuming():
    b = BanditAlgorithm()
    b.arm("a1", 5)
    before = len(b.audit_log())
    with pytest.raises(ba.SeqOrderError):
        b.arm("a2", 5)  # rewind: raises bare
    with pytest.raises(ba.SeqOrderError):
        b.arm("a2", True)
    with pytest.raises(ba.SeqOrderError):
        b.arm("a2", -1)
    with pytest.raises(ba.SeqOrderError):
        b.arm("a2", "7")
    assert len(b.audit_log()) == before  # nothing consumed, no audit row
    b.arm("a2", 6)  # fresh seq still works


# ---------------------------------------------------------------------------
# pull
# ---------------------------------------------------------------------------


def test_pull_roundtrip_and_ids():
    b = BanditAlgorithm()
    b.arm("a", 1)
    b.arm("b", 2)
    p1 = b.pull("a", 3)
    p2 = b.pull("a", 4)
    p3 = b.pull("b", 5)
    assert (p1.pull_id, p2.pull_id, p3.pull_id) == ("pull-1", "pull-2", "pull-3")
    assert p1.arm_id == "a" and p1.seq == 3
    assert p1.digest.startswith("sha256:")
    assert p1.verify("a")
    assert not p1.verify("b")
    assert b.pull_record("pull-2") == p2
    assert b.pull_record("nope") is None
    assert b.total_pulls() == 3


def test_pull_unknown_arm_consumes_seq_and_audits_rejected():
    b = BanditAlgorithm()
    with pytest.raises(ba.UnknownArmError):
        b.pull("ghost", 1)
    rejected = [r for r in b.audit_log() if r["kind"] == ba.KIND_REJECTED]
    assert len(rejected) == 1
    assert b.total_pulls() == 0


# ---------------------------------------------------------------------------
# reward
# ---------------------------------------------------------------------------


def test_reward_roundtrip_and_digest():
    b = BanditAlgorithm()
    b.arm("a", 1)
    p = b.pull("a", 2)
    rec = b.reward(p.pull_id, 0.75, 3)
    assert rec.pull_id == p.pull_id
    assert rec.arm_id == "a"
    assert rec.value == 0.75
    assert rec.digest.startswith("sha256:")
    assert rec.verify("a", 0.75)
    assert not rec.verify("a", 0.25)
    assert b.reward_record(p.pull_id) == rec
    assert b.reward_record("pull-9") is None


def test_reward_int_accepted_bool_and_range_refused():
    b = BanditAlgorithm()
    b.arm("a", 1)
    p1 = b.pull("a", 2)
    assert b.reward(p1.pull_id, 1, 3).value == 1.0  # int 1 stored as float
    p0 = b.pull("a", 4)
    assert b.reward(p0.pull_id, 0, 5).value == 0.0  # int 0 stored as float
    s = 6
    for bad in (True, float("nan"), float("inf"), -0.1, 1.1,
                "0.5", None, [1.0]):
        q = b.pull("a", s)
        s += 1
        with pytest.raises(ba.BadRewardError):
            b.reward(q.pull_id, bad, s)
        s += 1
    rejected = [r for r in b.audit_log() if r["kind"] == ba.KIND_REJECTED]
    assert len(rejected) == 8  # failed rewards consume seq + audit row


def test_reward_unknown_pull_and_duplicate():
    b = BanditAlgorithm()
    b.arm("a", 1)
    p = b.pull("a", 2)
    with pytest.raises(ba.UnknownPullError):
        b.reward("pull-404", 0.5, 3)
    b.reward(p.pull_id, 0.5, 4)
    with pytest.raises(ba.DuplicateRewardError):
        b.reward(p.pull_id, 0.9, 5)
    stats = {s.arm_id: s for s in b.stats(5)}
    assert stats["a"].pulls == 1 and stats["a"].rewards == 1
    assert stats["a"].mean == 0.5


# ---------------------------------------------------------------------------
# policy: scores + recommend
# ---------------------------------------------------------------------------


def test_recommend_explores_unpulled_first_then_exploits():
    b = BanditAlgorithm()
    b.arm("z-arm", 1)
    b.arm("a-arm", 2)
    # Unpulled arms score +inf: lowest arm_id explored first.
    rec = b.recommend(3)
    assert rec.arm_id == "a-arm"
    assert rec.scores == (("a-arm", float("inf")),
                          ("z-arm", float("inf")))
    # Book rewards: a-arm good (1.0), z-arm bad (0.0).
    b.reward(b.pull("a-arm", 4).pull_id, 1.0, 5)
    b.reward(b.pull("z-arm", 6).pull_id, 0.0, 7)
    rec = b.recommend(8)
    assert rec.arm_id == "a-arm"
    assert rec.digest.startswith("sha256:")
    assert rec.verify("a-arm", 8, rec.scores)
    scores = dict(rec.scores)
    assert scores["a-arm"] > scores["z-arm"]


def test_ucb_scores_pure_read_and_tie_break_deterministic():
    b = BanditAlgorithm()
    b.arm("m", 1)
    b.arm("n", 2)
    view = b.ucb_scores(2)  # seq reuse allowed: read-only
    assert view.scores == (("m", float("inf")), ("n", float("inf")))
    # All pulls on m with reward 0.5 twice: equal scores -> lowest arm_id.
    b.reward(b.pull("m", 3).pull_id, 0.5, 4)
    b.reward(b.pull("n", 5).pull_id, 0.5, 6)
    rec = b.recommend(7)
    assert rec.arm_id == "m"
    assert b.ucb_scores(7).scores == rec.scores


def test_recommend_no_arms_fail_closed():
    b = BanditAlgorithm()
    with pytest.raises(ba.NoArmsError):
        b.recommend(1)
    assert len(b.audit_log()) == 1  # rejected row booked


# ---------------------------------------------------------------------------
# audit boundary
# ---------------------------------------------------------------------------


def test_audit_shapes_and_reward_leak_ban_and_bad_kind():
    b = BanditAlgorithm()
    b.arm("a", 1)
    p = b.pull("a", 2)
    b.reward(p.pull_id, 0.123456789, 3)
    b.recommend(4)
    kinds = {r["kind"] for r in b.audit_log()}
    assert kinds == {ba.KIND_ARM_REGISTERED, ba.KIND_PULLED,
                     ba.KIND_REWARDED, ba.KIND_RECOMMENDED}
    for row in b.audit_log():
        assert row["schema"] == ba.AUDIT_SCHEMA
        assert row["module"] == ba.BANDIT_ALGORITHM_VERSION
    blob = str(b.audit_log())
    assert "0.123456789" not in blob  # raw reward value stays out
    with pytest.raises(ba.AuditKindError):
        ba.bandit_algorithm_audit_event("bogus-kind", {}, 5)
    with pytest.raises(ba.AuditKindError):
        ba.bandit_algorithm_audit_event(ba.KIND_REWARDED, {"value": 1.0}, 5)


# ---------------------------------------------------------------------------
# main self-check
# ---------------------------------------------------------------------------


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, _module_path()],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0
    assert "bandit-algorithm OK" in proc.stdout
