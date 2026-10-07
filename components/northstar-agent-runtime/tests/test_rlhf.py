"""Tests for rlhf: 15 cases."""

import ast
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import rlhf
from rlhf import (
    RLHF,
    AuditKindError,
    BadDigestError,
    BadPolicyError,
    BadPreferenceError,
    BadRewardError,
    BadTrainError,
    DuplicatePolicyError,
    SeqOrderError,
    UnknownPolicyError,
    UnknownRewardError,
    rlhf_audit_event,
)


def _r():
    return RLHF()


def _digest(ch):
    return "sha256:" + ch * 64


def _policy(r, pid="pol-1", seq=1):
    return r.register_policy(pid, seq=seq)


def test_01_version_and_schema_pins():
    assert rlhf.RLHF_VERSION == "rlhf.v1"
    assert rlhf.RLHF_SCHEMA == "northstar.rlhf.v1"
    assert rlhf.AUDIT_SCHEMA == "audit.ndjson/1"


def test_02_stdlib_only():
    path = os.path.join(os.path.dirname(__file__), "..", "rlhf.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    allowed = {
        "hashlib", "math", "re", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_03_register_policy_roundtrip():
    r = _r()
    rec = _policy(r, "sft-7b", seq=1)
    assert rec.policy_id == "sft-7b"
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    assert rec.version == "rlhf.v1"
    assert r.policy_ids() == ("sft-7b",)
    assert r.policy("sft-7b") == rec


def test_04_register_policy_bad_inputs_burn_seq():
    r = _r()
    _policy(r, "pol-a", seq=1)
    for seq, pid in ((2, "pol-a"), (3, ""), (4, None), (5, 7)):
        try:
            r.register_policy(pid, seq=seq)
        except (DuplicatePolicyError, BadPolicyError, TypeError,
                ValueError) as e:
            pass
        else:
            raise AssertionError(f"seq={seq} pid={pid!r} should refuse")
    rejected = [row for row in r.audit_log() if row["kind"] == "rejected"]
    assert len(rejected) == 4, r.audit_log()
    # seqs were consumed: the next valid booking needs a fresh seq.
    rec = r.register_policy("pol-b", seq=6)
    assert rec.policy_id == "pol-b"


def test_05_preference_roundtrip():
    r = _r()
    pref = r.preference(_digest("a"), _digest("b"), _digest("c"), seq=1)
    assert pref.preference_id == "pref-1"
    assert pref.verify()
    assert pref.better_digest != pref.worse_digest
    assert r.preference_record("pref-1") == pref
    assert r.preference_ids() == ("pref-1",)


def test_06_preference_bad_inputs_burn_seq():
    r = _r()
    cases = [
        # (prompt, better, worse)
        (_digest("a"), _digest("b"), _digest("b")),  # better == worse
        ("raw prompt text", _digest("b"), _digest("c")),  # raw text refused
        (_digest("a"), "not-a-digest", _digest("c")),
        (_digest("a"), _digest("b"), "SHA256:" + "D" * 64),  # uppercase
        (None, _digest("b"), _digest("c")),
    ]
    seq = 1
    for prompt, better, worse in cases:
        try:
            r.preference(prompt, better, worse, seq=seq)
        except (BadDigestError, BadPreferenceError):
            pass
        else:
            raise AssertionError(f"seq={seq} should refuse")
        seq += 1
    rejected = [row for row in r.audit_log() if row["kind"] == "rejected"]
    assert len(rejected) == len(cases), r.audit_log()


def test_07_reward_roundtrip():
    r = _r()
    _policy(r, "pol-1", seq=1)
    rec = r.reward(_digest("a"), seq=2, value=0.75,
                   prompt_digest=_digest("b"), policy_id="pol-1")
    assert rec.reward_id == "rew-1"
    assert rec.value == 0.75
    assert rec.verify()
    assert r.reward_record("rew-1") == rec
    assert r.reward_ids() == ("rew-1",)


def test_08_reward_bad_values_burn_seq():
    r = _r()
    _policy(r, "pol-1", seq=1)
    bad_values = [True, float("nan"), float("inf"), -0.1, 1.1, "high", None]
    seq = 2
    for value in bad_values:
        try:
            r.reward(_digest("a"), seq=seq, value=value, policy_id="pol-1")
        except BadRewardError:
            pass
        else:
            raise AssertionError(f"seq={seq} value={value!r} should refuse")
        seq += 1
    # unknown policy is also refused fail-closed
    try:
        r.reward(_digest("a"), seq=seq, value=0.5, policy_id="ghost")
    except UnknownPolicyError:
        pass
    else:
        raise AssertionError("unknown policy should refuse")
    rejected = [row for row in r.audit_log() if row["kind"] == "rejected"]
    assert len(rejected) == len(bad_values) + 1, r.audit_log()


def test_09_train_roundtrip():
    r = _r()
    _policy(r, "pol-1", seq=1)
    rew = r.reward(_digest("a"), seq=2, value=0.9, policy_id="pol-1")
    step = r.train("pol-1", seq=3, reward_ids=[rew.reward_id],
                   kl=0.05, loss=1.25)
    assert step.train_id == "train-1"
    assert step.reward_ids == (rew.reward_id,)
    assert step.kl == 0.05 and step.loss == 1.25
    assert step.verify()
    assert r.train_record("train-1") == step


def test_10_train_bad_inputs_burn_seq():
    r = _r()
    _policy(r, "pol-1", seq=1)
    rew = r.reward(_digest("a"), seq=2, value=0.5, policy_id="pol-1")
    cases = [
        # (reward_ids, kl, loss)
        (["rew-999"], 0.0, 0.0),          # unknown reward
        ([rew.reward_id], float("nan"), 0.0),
        ([rew.reward_id], -0.1, 0.0),     # negative KL
        ([rew.reward_id], 0.0, float("inf")),
        ([], 0.0, 0.0),                   # empty batch
        ([""], 0.0, 0.0),
    ]
    seq = 3
    for reward_ids, kl, loss in cases:
        try:
            r.train("pol-1", seq=seq, reward_ids=reward_ids, kl=kl, loss=loss)
        except (UnknownRewardError, BadTrainError):
            pass
        else:
            raise AssertionError(f"seq={seq} should refuse")
        seq += 1
    # unknown policy
    try:
        r.train("ghost", seq=seq, reward_ids=[rew.reward_id])
    except UnknownPolicyError:
        pass
    else:
        raise AssertionError("unknown policy should refuse")
    rejected = [row for row in r.audit_log() if row["kind"] == "rejected"]
    assert len(rejected) == len(cases) + 1, r.audit_log()


def test_11_evaluate_read_purity():
    r = _r()
    _policy(r, "pol-1", seq=1)
    # empty ledger is data, never raised
    report = r.evaluate("pol-1", seq=1)  # seq reuse fine on pure reads
    assert report.reward_count == 0
    assert report.mean_reward == 0.0
    assert report.train_steps == 0
    assert report.kl_budget_exceeded is False
    assert report.verify()
    audit_before = len(r.audit_log())
    rew = r.reward(_digest("a"), seq=2, value=0.8, policy_id="pol-1")
    r.train("pol-1", seq=3, reward_ids=[rew.reward_id], kl=0.3)
    audit_after_writes = len(r.audit_log())
    report2 = r.evaluate("pol-1", seq=3)  # same seq twice OK
    report3 = r.evaluate("pol-1", seq=3)
    assert report2.reward_count == 1 and report2.mean_reward == 0.8
    assert report2.train_steps == 1
    assert report2.kl_budget_exceeded is True  # 0.3 > KL_BUDGET 0.2
    assert report2.verify()
    assert report3 == report2
    # pure reads write no audit rows
    assert len(r.audit_log()) == audit_after_writes
    assert audit_before == 1  # only the register row
    # unknown policy refuses (shape error, no seq burn needed)
    try:
        r.evaluate("ghost", seq=4)
    except UnknownPolicyError:
        pass
    else:
        raise AssertionError("unknown policy should refuse")


def test_12_seq_ordering():
    r = _r()
    _policy(r, "pol-1", seq=1)
    # rewind raises bare, consumes nothing, books no rejected row
    for bad_seq in (1, 0, True, "2", 2.0, -1, None):
        try:
            r.preference(_digest("a"), _digest("b"), _digest("c"), seq=bad_seq)
        except (SeqOrderError, TypeError, ValueError):
            pass
        else:
            raise AssertionError(f"seq={bad_seq!r} should refuse")
    rejected = [row for row in r.audit_log() if row["kind"] == "rejected"]
    assert not rejected, r.audit_log()
    # fresh seq still works after bare rewinds
    pref = r.preference(_digest("a"), _digest("b"), _digest("c"), seq=2)
    assert pref.preference_id == "pref-1"


def test_13_audit_shapes_and_leak_ban():
    # builder accepts good kinds
    row = rlhf_audit_event("policy-registered", {"policy_id": "p"}, 1)
    assert row["event"] == "rlhf"
    assert row["schema"] == "audit.ndjson/1"
    # bad kind refused
    try:
        rlhf_audit_event("nope", {}, 1)
    except AuditKindError:
        pass
    else:
        raise AssertionError("bad kind should refuse")
    # raw material banned from the audit boundary
    for banned in ("prompt", "value", "kl", "loss", "response", "better"):
        try:
            rlhf_audit_event("reward-booked", {banned: "x"}, 1)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{banned} should be banned")
    # end-to-end: no audit row carries banned keys
    r = _r()
    _policy(r, "pol-1", seq=1)
    r.preference(_digest("a"), _digest("b"), _digest("c"), seq=2)
    r.reward(_digest("b"), seq=3, value=0.4, policy_id="pol-1")
    banned = {"prompt", "response", "better", "worse", "text", "value",
              "kl", "loss", "payload", "raw", "rewards", "pairs"}
    for row in r.audit_log():
        detail = row["detail"]
        assert not (set(detail) & banned), row


def test_14_cross_instance_determinism_and_frozen():
    def _build():
        r = _r()
        r.register_policy("pol-1", seq=1, base_digest=_digest("0"))
        r.preference(_digest("a"), _digest("b"), _digest("c"), seq=2)
        r.reward(_digest("b"), seq=3, value=0.6, policy_id="pol-1")
        return r

    r1, r2 = _build(), _build()
    assert r1.policy("pol-1").digest == r2.policy("pol-1").digest
    assert (r1.preference_record("pref-1").digest
            == r2.preference_record("pref-1").digest)
    assert r1.reward_record("rew-1").digest == r2.reward_record("rew-1").digest
    # frozen records
    import dataclasses

    rec = r1.policy("pol-1")
    try:
        object.__setattr__  # noqa: B018 - existence probe only
        rec.policy_id = "mutated"  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("PolicyRecord should be frozen")
    # tamper breaks verify
    tampered = dataclasses.replace(rec, base_digest=_digest("f"))
    assert not tampered.verify()


def test_15_main_self_check():
    here = os.path.join(os.path.dirname(__file__), "..")
    result = subprocess.run(
        [sys.executable, os.path.join(here, "rlhf.py")],
        capture_output=True, text=True, cwd=here, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().startswith("rlhf OK:"), result.stdout
