"""Targeted tests for the IRL ledger (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import irl as I
from irl import IRL

RUNTIME_DIR = Path(__file__).resolve().parent.parent
PIN = "sha256:" + "0" * 64
PIN2 = "sha256:" + "a" * 64
PIN3 = "sha256:" + "f" * 64


def test_version_and_schema_pins():
    assert I.IRL_VERSION == "irl.v1"
    assert I.SCHEMA_PIN == "northstar.irl.v1"
    assert I.AUDIT_SCHEMA == "audit.ndjson/1"
    assert I.AUDIT_KINDS == ("observed", "inferred", "retired", "rejected")
    assert set(I.INFERENCE_METHODS) == {
        "ng-and-russell", "maximum-entropy", "apprenticeship", "gail",
        "airl", "bair", "max-margin", "behavioral-cloning"}
    assert set(I.INFERENCE_OUTCOMES) == {
        "recovered", "ambiguous", "inconclusive"}


def test_stdlib_only_imports():
    tree = ast.parse((RUNTIME_DIR / "irl.py").read_text())
    allowed = {"hashlib", "re", "threading", "dataclasses", "typing",
               "__future__", "canonical_json", "json", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module
    assert IRL.stdlib_only()


def test_observe_roundtrip_and_verify():
    irl = IRL()
    rec = irl.observe("traj-1", "agent-1", 1, PIN)
    assert rec.trajectory_id == "traj-1"
    assert rec.agent_id == "agent-1"
    assert rec.trajectory_digest == PIN
    assert rec.verify()
    # empty digest is allowed
    rec2 = irl.observe("traj-2", "agent-1", 2)
    assert rec2.trajectory_digest == ""
    assert rec2.verify()
    # frozen
    with pytest.raises(Exception):
        rec.trajectory_id = "traj-x"  # frozen


def test_observe_bad_inputs_seq_burn_and_rejected_rows():
    irl = IRL()
    seq = 0
    bad = [
        {"trajectory_id": "", "agent_id": "a1"},
        {"trajectory_id": "has space", "agent_id": "a1"},
        {"trajectory_id": "x" * 257, "agent_id": "a1"},
        {"trajectory_id": 7, "agent_id": "a1"},
        {"trajectory_id": True, "agent_id": "a1"},
        {"trajectory_id": "t1", "agent_id": ""},
        {"trajectory_id": "t1", "agent_id": "a1",
         "trajectory_digest": "not-a-pin"},
        {"trajectory_id": "t1", "agent_id": "a1",
         "trajectory_digest": "sha256:" + "g" * 64},
    ]
    for kwargs in bad:
        seq += 1
        with pytest.raises(I.IRLError):
            irl.observe(seq=seq, **kwargs)
    # each failed mutation burned its seq and booked a rejected row
    assert seq == sum(
        1 for e in irl.audit_log(99) if e["kind"] == "irl.rejected")
    # duplicate refusal burns seq too
    irl.observe("dup-1", "a1", 100)
    with pytest.raises(I.DuplicateTrajectoryError):
        irl.observe("dup-1", "a1", 101)
    rows = irl.audit_log(102)
    assert sum(1 for e in rows if e["kind"] == "irl.rejected") == seq + 1


def test_infer_roundtrip_minting_and_full_method_vocabulary():
    irl = IRL()
    irl.observe("traj-1", "agent-1", 1, PIN)
    for i, method in enumerate(I.INFERENCE_METHODS):
        rec = irl.infer("agent-1", i + 2, method=method,
                        outcome="recovered", reward_digest=PIN2)
        assert rec.inference_id == f"inf-{i + 1}"
        assert rec.method == method
        assert rec.verify()
    assert irl.inferences_for("agent-1", 20) == tuple(
        f"inf-{i}" for i in range(1, 9))
    # all outcomes accepted
    irl2 = IRL()
    irl2.observe("t-1", "a-9", 1)
    for outcome in I.INFERENCE_OUTCOMES:
        r = irl2.infer("a-9", irl2._last_seq + 1, outcome=outcome)
        assert r.outcome == outcome


def test_infer_refusals_seq_burn():
    irl = IRL()
    irl.observe("traj-1", "agent-1", 1)
    seq = 1
    cases = [
        ({"agent_id": "ghost", "method": "gail"}, I.UnknownAgentError),
        ({"agent_id": "agent-1", "method": "vibes"}, I.BadMethodError),
        ({"agent_id": "agent-1", "method": 7}, I.BadMethodError),
        ({"agent_id": "agent-1", "outcome": "definitely"}, I.BadOutcomeError),
        ({"agent_id": "agent-1", "reward_digest": "raw-bytes"},
         I.BadDigestError),
        ({"agent_id": "", "method": "gail"}, I.BadIdError),
    ]
    for kwargs, exc in cases:
        seq += 1
        with pytest.raises(exc):
            irl.infer(seq=seq, **kwargs)
    assert sum(1 for e in irl.audit_log(99)
               if e["kind"] == "irl.rejected") == len(cases)


def test_evaluate_read_purity_and_math():
    irl = IRL()
    irl.observe("traj-1", "agent-1", 1)
    irl.observe("traj-2", "agent-1", 2)
    irl.infer("agent-1", 3, method="gail", outcome="ambiguous")
    n_audit = len(irl.audit_log(4))
    rep1 = irl.evaluate("agent-1", 4)
    rep2 = irl.evaluate("agent-1", 4)
    assert rep1.n_trajectories == 2
    assert rep1.n_inferences == 1
    assert rep1.latest_method == "gail"
    assert rep1.latest_outcome == "ambiguous"
    assert rep1.integrity_ok
    assert rep1.verify() and rep2.verify()
    # reads add no rows and consume no seq
    assert len(irl.audit_log(4)) == n_audit
    # unknown agent refused, no burn
    with pytest.raises(I.UnknownAgentError):
        irl.evaluate("ghost", 4)


def test_retire_terminality_and_id_non_recycling():
    irl = IRL()
    irl.observe("traj-1", "agent-1", 1)
    rec = irl.retire("agent-1", 2, reason="task-complete")
    assert rec.reason == "task-complete"
    assert rec.verify()
    assert irl.retired_ids(3) == ("agent-1",)
    # post-retire mutations refused
    with pytest.raises(I.RetiredAgentError):
        irl.observe("traj-2", "agent-1", 4)
    with pytest.raises(I.RetiredAgentError):
        irl.infer("agent-1", 5)
    with pytest.raises(I.RetiredAgentError):
        irl.retire("agent-1", 6)
    # reads still work
    assert irl.evaluate("agent-1", 7).n_trajectories == 1
    assert irl.trajectories_for("agent-1", 8) == ("traj-1",)
    # bad reason burns seq
    irl.observe("t-9", "agent-9", 9)
    with pytest.raises(I.BadReasonError):
        irl.retire("agent-9", 10, reason="vibes")
    # unknown agent refused
    with pytest.raises(I.UnknownAgentError):
        irl.retire("ghost", 11)
    # all retire reasons accepted
    irl2 = IRL()
    for i, reason in enumerate(I.RETIRE_REASONS):
        irl2.observe(f"rt-{i}", f"ag-{i}", 1 if i == 0 else irl2._last_seq + 1)
        r = irl2.retire(f"ag-{i}", irl2._last_seq + 1, reason=reason)
        assert r.reason == reason


def test_seq_discipline_rewind_bare_malformed_and_failed_burn():
    irl = IRL()
    irl.observe("traj-1", "agent-1", 5, PIN)
    # rewind raises bare with zero rejected rows
    with pytest.raises(I.SeqOrderError):
        irl.observe("traj-2", "agent-1", 5)
    assert irl.stats(6)["rejected"] == 0
    # malformed seqs: 0 is well-formed but a rewind; others are BadSeqError
    for bad in (True, 0, -1, 1.5, "2", None):
        expect = I.SeqOrderError if bad in (0, 5) else I.BadSeqError
        with pytest.raises(expect):
            irl.observe("traj-x", "agent-1", bad)
    # failed mutation consumes seq: next good seq must be strictly larger
    with pytest.raises(I.BadMethodError):
        irl.infer("agent-1", 6, method="vibes")
    with pytest.raises(I.SeqOrderError):
        irl.infer("agent-1", 6, method="gail")
    rec = irl.infer("agent-1", 7, method="gail")
    assert rec.inference_id == "inf-1"


def test_audit_shapes_and_leak_ban():
    irl = IRL()
    irl.observe("traj-1", "agent-1", 1, PIN)
    irl.infer("agent-1", 2, method="airl", outcome="ambiguous",
              reward_digest=PIN2)
    irl.retire("agent-1", 3, reason="superseded")
    rows = irl.audit_log(4)
    assert [r["kind"] for r in rows] == [
        "irl.observed", "irl.inferred", "irl.retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in I._BANNED_AUDIT_KEYS
    # banned keys rejected at the builder
    with pytest.raises(I.AuditKindError):
        I.irl_audit_event("observed", 5, trajectory="raw-states")
    with pytest.raises(I.AuditKindError):
        I.irl_audit_event("inferred", 5, reward="raw-weights")
    with pytest.raises(I.AuditKindError):
        I.irl_audit_event("bogus-kind", 5)
    with pytest.raises(I.BadSeqError):
        I.irl_audit_event("observed", -1)


def test_cross_instance_digest_determinism_and_tamper_breaks_verify():
    def build():
        irl = IRL()
        irl.observe("traj-1", "agent-1", 1, PIN)
        irl.infer("agent-1", 2, method="ng-and-russell",
                  outcome="recovered", reward_digest=PIN3)
        return irl

    a, b = build(), build()
    assert (a.trajectory_record("traj-1", 3).digest
            == b.trajectory_record("traj-1", 3).digest)
    assert (a.inference_record("inf-1", 3).digest
            == b.inference_record("inf-1", 3).digest)
    import dataclasses
    tampered = dataclasses.replace(
        a.inference_record("inf-1", 3), outcome="ambiguous")
    assert tampered.verify() is False
    # tamper reported as data via integrity_ok: still True before mutation
    assert a.evaluate("agent-1", 4).integrity_ok is True
    # mutate the stored record in place: digest no longer matches
    stored = a.inference_record("inf-1", 3)
    object.__setattr__(stored, "outcome", "ambiguous")
    assert stored.verify() is False
    assert a.evaluate("agent-1", 4).integrity_ok is False


def test_views_and_stats():
    irl = IRL()
    irl.observe("traj-1", "agent-1", 1)
    irl.observe("traj-2", "agent-2", 2)
    irl.infer("agent-1", 3, method="bair")
    assert irl.agent_ids(4) == ("agent-1", "agent-2")
    assert irl.trajectories_for("agent-1", 5) == ("traj-1",)
    assert irl.inferences_for("agent-2", 5) == ()
    assert irl.stats(6) == {
        "agents": 2, "trajectories": 2, "inferences": 1,
        "retired": 0, "rejected": 0}
    with pytest.raises(I.UnknownTrajectoryError):
        irl.trajectory_record("ghost", 7)
    with pytest.raises(I.UnknownAgentError):
        irl.trajectories_for("ghost", 7)


def test_full_lifecycle_end_to_end():
    irl = IRL()
    irl.observe("demo-1", "demo-agent", 1, PIN)
    inf = irl.infer("demo-agent", 2, method="maximum-entropy",
                    outcome="recovered", reward_digest=PIN2)
    assert inf.inference_id == "inf-1"
    rep = irl.evaluate("demo-agent", 3)
    assert (rep.n_trajectories, rep.n_inferences) == (1, 1)
    assert rep.latest_method == "maximum-entropy"
    assert rep.latest_outcome == "recovered"
    assert rep.integrity_ok and rep.verify()
    irl.retire("demo-agent", 4)
    assert irl.retired_ids(5) == ("demo-agent",)
    assert irl.stats(6)["retired"] == 1


def test_concurrency_and_frozen():
    irl = IRL()
    for i in range(10):
        irl.observe(f"tr-{i}", f"ag-{i % 3}", i * 2 + 1)
    results = []

    def worker():
        results.append(irl.agent_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 3 for r in results)
    rec = irl.trajectory_record("tr-0", 100)
    with pytest.raises(Exception):
        rec.trajectory_id = "tr-x"  # frozen
    assert rec.verify()


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(RUNTIME_DIR / "irl.py")],
        capture_output=True,
        text=True,
        cwd=str(RUNTIME_DIR),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "irl OK: observe, infer, evaluate, retire, pins, audit")
