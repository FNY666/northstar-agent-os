"""Tests for cooperative_irl (cooperative-IRL game decision ledger, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import cooperative_irl as cirl
from cooperative_irl import (
    COOPERATIVE_IRL_VERSION,
    SCHEMA_PIN,
    ROLES,
    ACTION_KINDS,
    LEARNING_KINDS,
    LEARNING_OUTCOMES,
    POSTURES,
    RETIRE_REASONS,
    AUDIT_KINDS,
    CooperativeIRL,
    cooperative_irl_audit_event,
)

MOD = Path(cirl.__file__)

STDLIB_ALLOW = {
    "hashlib", "json", "threading", "dataclasses", "typing", "__future__",
    "canonical_json", "ast", "pathlib",
}


def _digest(tag: bytes = b"cir") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _led() -> CooperativeIRL:
    return CooperativeIRL()


# 1. version/schema/vocabulary pins
def test_pins():
    assert COOPERATIVE_IRL_VERSION == "cooperative-irl.v1"
    assert SCHEMA_PIN == "northstar.cooperative-irl.v1"
    assert ROLES == ("human", "robot")
    assert len(ACTION_KINDS) == 8 and "demonstration" in ACTION_KINDS
    assert "correction" in ACTION_KINDS and "approval" in ACTION_KINDS
    assert len(LEARNING_KINDS) == 6 and "reward-inference" in LEARNING_KINDS
    assert "deference-increase" in LEARNING_KINDS
    assert len(LEARNING_OUTCOMES) == 4 and "improved" in LEARNING_OUTCOMES
    assert "regressed" in LEARNING_OUTCOMES
    assert POSTURES == ("uncoordinated", "misaligned", "inconclusive", "cooperative")
    assert len(RETIRE_REASONS) == 4 and "team-disbanded" in RETIRE_REASONS
    assert set(AUDIT_KINDS) == {"teamed", "interacted", "learned", "retired", "rejected"}


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW
    assert CooperativeIRL.stdlib_only()


# 3. register roundtrip + verify + frozen-ness
def test_register_roundtrip():
    c = _led()
    rec = c.register_team("team-a", 1, human_digest=_digest(b"h"),
                          robot_digest=_digest(b"r"))
    assert rec.team_id == "team-a"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    assert c.team_record("team-a", 2).verify()
    assert c.team_ids(2) == ("team-a",)
    with pytest.raises(Exception):
        rec.team_id = "team-b"  # frozen


# 4. register bad-input table + seq-burn + rejected-row accounting + duplicate
def test_register_bad_inputs():
    c = _led()
    seq = 0
    bad = [
        (lambda q: c.register_team("", q), cirl.BadIdError),
        (lambda q: c.register_team(123, q), cirl.BadIdError),
        (lambda q: c.register_team("t1", q, human_digest="raw"), cirl.BadDigestError),
        (lambda q: c.register_team("t1", q, robot_digest="md5:abc"), cirl.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    seq += 1
    c.register_team("t1", seq)
    seq += 1
    with pytest.raises(cirl.DuplicateTeamError):
        c.register_team("t1", seq)  # duplicate burns seq
    assert c.stats(seq + 1)["rejected"] == len(bad) + 1
    assert c.stats(seq + 1)["teams"] == 1


# 5. interact roundtrip + minted ids + verify + frozen-ness
def test_interact_roundtrip():
    c = _led()
    c.register_team("t1", 1)
    r1 = c.interact("t1", 2, role="human", action_kind="demonstration",
                    action_digest=_digest())
    assert r1.interaction_id == "int-1"
    assert r1.role == "human" and r1.action_kind == "demonstration"
    assert r1.verify()
    assert r1.as_dict()["schema"] == SCHEMA_PIN
    r2 = c.interact("t1", 3, role="robot", action_kind="query")
    assert r2.interaction_id == "int-2"
    assert c.interactions_for("t1", 4) == ("int-1", "int-2")
    assert c.interaction_record("int-1", 4).verify()
    with pytest.raises(Exception):
        r1.action_kind = "correction"  # frozen


# 6. interact bad-input table + seq-burn + rejected-row accounting
def test_interact_bad_inputs():
    c = _led()
    c.register_team("t1", 1)
    seq = 1
    bad = [
        (lambda q: c.interact("", q), cirl.BadIdError),
        (lambda q: c.interact("ghost", q), cirl.UnknownTeamError),
        (lambda q: c.interact("t1", q, role="supervisor"), cirl.BadRoleError),
        (lambda q: c.interact("t1", q, action_kind="mind-reading"), cirl.BadActionKindError),
        (lambda q: c.interact("t1", q, action_digest="raw-bytes"), cirl.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert c.stats(seq + 1)["rejected"] == len(bad)
    assert c.stats(seq + 1)["interactions"] == 0


# 7. full action-kind x role vocabulary acceptance
def test_interact_full_vocabulary():
    c = _led()
    c.register_team("t1", 1)
    seq = 1
    for kind in ACTION_KINDS:
        for role in ROLES:
            seq += 1
            rec = c.interact("t1", seq, role=role, action_kind=kind)
            assert rec.verify()
    assert c.stats(seq + 1)["interactions"] == len(ACTION_KINDS) * len(ROLES)


# 8. learn roundtrip + minted ids + verify
def test_learn_roundtrip():
    c = _led()
    c.register_team("t1", 1)
    c.interact("t1", 2, role="human", action_kind="demonstration")
    r1 = c.learn("t1", 3, learning_kind="reward-inference", outcome="improved",
                 belief_digest=_digest())
    assert r1.learning_id == "lrn-1"
    assert r1.learning_kind == "reward-inference" and r1.outcome == "improved"
    assert r1.verify()
    assert r1.as_dict()["schema"] == SCHEMA_PIN
    r2 = c.learn("t1", 4, learning_kind="deference-increase", outcome="unchanged")
    assert r2.learning_id == "lrn-2"
    assert c.learnings_for("t1", 5) == ("lrn-1", "lrn-2")
    assert c.learning_record("lrn-1", 5).verify()
    with pytest.raises(Exception):
        r1.outcome = "regressed"  # frozen


# 9. learn bad-input table + seq-burn + full learning-kind acceptance
def test_learn_bad_inputs_and_vocabulary():
    c = _led()
    c.register_team("t1", 1)
    seq = 1
    bad = [
        (lambda q: c.learn("", q), cirl.BadIdError),
        (lambda q: c.learn("ghost", q), cirl.UnknownTeamError),
        (lambda q: c.learn("t1", q, learning_kind="telepathy"), cirl.BadLearningKindError),
        (lambda q: c.learn("t1", q, outcome="ascended"), cirl.BadOutcomeError),
        (lambda q: c.learn("t1", q, belief_digest="raw"), cirl.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert c.stats(seq + 1)["rejected"] == len(bad)
    for kind in LEARNING_KINDS:
        seq += 1
        rec = c.learn("t1", seq, learning_kind=kind, outcome="inconclusive")
        assert rec.verify()
    assert c.stats(seq + 1)["learnings"] == len(LEARNING_KINDS)


# 10. evaluate posture math (all postures + precedence) + unknown refusal
def test_evaluate_posture_math():
    c = _led()
    c.register_team("t1", 1)
    c.register_team("t2", 2)
    c.register_team("t3", 3)
    c.register_team("t4", 4)
    # t1: no interactions -> uncoordinated
    rep = c.evaluate("t1", 5)
    assert rep.posture == "uncoordinated"
    assert rep.integrity_ok and rep.verify()
    # t2: interactions, no learning -> inconclusive
    c.interact("t2", 6, role="human", action_kind="demonstration")
    rep = c.evaluate("t2", 7)
    assert rep.posture == "inconclusive"
    assert rep.n_interactions == 1 and rep.n_learning == 0
    # t3: improved -> cooperative
    c.interact("t3", 8)
    c.learn("t3", 9, learning_kind="reward-inference", outcome="improved")
    rep = c.evaluate("t3", 10)
    assert rep.posture == "cooperative"
    assert rep.n_improved == 1 and rep.integrity_ok
    # t4: regressed beats improved (precedence) -> misaligned
    c.interact("t4", 11)
    c.learn("t4", 12, outcome="improved")
    c.learn("t4", 13, outcome="regressed")
    rep = c.evaluate("t4", 14)
    assert rep.posture == "misaligned"
    # unknown team refuses without consuming seq
    with pytest.raises(cirl.UnknownTeamError):
        c.evaluate("ghost", 15)
    # inconclusive-only -> inconclusive
    c2 = _led()
    c2.register_team("t1", 1)
    c2.interact("t1", 2)
    c2.learn("t1", 3, outcome="inconclusive")
    assert c2.evaluate("t1", 4).posture == "inconclusive"
    # unchanged-only -> inconclusive
    c3 = _led()
    c3.register_team("t1", 1)
    c3.interact("t1", 2)
    c3.learn("t1", 3, outcome="unchanged")
    assert c3.evaluate("t1", 4).posture == "inconclusive"


# 11. evaluate read purity: same-seq twice, no audit rows, views read-pure
def test_evaluate_read_purity():
    c = _led()
    c.register_team("t1", 1)
    c.interact("t1", 2, role="robot", action_kind="query")
    c.learn("t1", 3, outcome="improved")
    n_audit = len(c.audit_log(4))
    r1 = c.evaluate("t1", 4)
    r2 = c.evaluate("t1", 4)
    assert r1.verify() and r2.verify()
    assert r1.posture == r2.posture == "cooperative"
    assert len(c.audit_log(4)) == n_audit  # reads add no rows
    assert c.team_ids(4) == ("t1",)
    assert c.interaction_ids(4) == ("int-1",)
    assert c.learning_ids(4) == ("lrn-1",)
    assert c.retired_ids(4) == ()


# 12. retire terminality + id non-recycling + bad reason + reads still work
def test_retire_terminality():
    c = _led()
    c.register_team("t1", 1)
    c.interact("t1", 2)
    seq = 2
    seq += 1
    with pytest.raises(cirl.BadReasonError):
        c.retire("t1", seq, reason="vibes")
    seq += 1
    rec = c.retire("t1", seq, reason="team-complete")
    assert rec.verify() and rec.reason == "team-complete"
    seq += 1
    with pytest.raises(cirl.RetiredTeamError):
        c.retire("t1", seq)  # double retire refused
    # id never recycled
    seq += 1
    with pytest.raises(cirl.DuplicateTeamError):
        c.register_team("t1", seq)
    # post-retire mutations refused
    seq += 1
    with pytest.raises(cirl.RetiredTeamError):
        c.interact("t1", seq)
    seq += 1
    with pytest.raises(cirl.RetiredTeamError):
        c.learn("t1", seq)
    # reads still work
    assert c.retired_ids(seq + 1) == ("t1",)
    assert c.evaluate("t1", seq + 1).posture == "inconclusive"
    assert c.stats(seq + 1)["retired"] == 1
    # unknown team retire refused
    seq += 1
    with pytest.raises(cirl.UnknownTeamError):
        c.retire("ghost", seq)


# 13. seq discipline: rewind bare with zero rows, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    c = _led()
    c.register_team("t1", 5)
    with pytest.raises(cirl.SeqOrderError):
        c.register_team("t2", 5)  # rewind: bare
    assert c.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(cirl.SeqOrderError):
            c.interact("t1", bad)
    assert c.stats(6)["rejected"] == 0
    c.interact("t1", 7)
    assert c.stats(8)["interactions"] == 1
    # failed mutation consumes seq: reusing it is a rewind
    with pytest.raises(cirl.BadRoleError):
        c.interact("t1", 8, role="boss")
    with pytest.raises(cirl.SeqOrderError):
        c.interact("t1", 8)
    assert c.stats(9)["rejected"] == 1


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    c = _led()
    c.register_team("t1", 1)
    c.interact("t1", 2, role="human", action_kind="demonstration")
    c.learn("t1", 3, outcome="improved")
    with pytest.raises(cirl.BadRoleError):
        c.interact("t1", 4, role="boss")
    c.retire("t1", 5, reason="manual")
    rows = c.audit_log(6)
    assert [r["kind"] for r in rows] == ["teamed", "interacted", "learned",
                                         "rejected", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in cirl._BANNED_AUDIT_KEYS
    # pinned vocabulary values remain emittable as declared data
    kinds = [r["kind"] for r in rows]
    interacted = rows[kinds.index("interacted")]
    assert interacted["details"]["role"] == "human"
    assert interacted["details"]["action_kind"] == "demonstration"
    with pytest.raises(cirl.AuditKindError):
        cooperative_irl_audit_event("interacted", 1, demonstration="raw")
    with pytest.raises(cirl.AuditKindError):
        cooperative_irl_audit_event("bogus-kind", 1)
    with pytest.raises(cirl.SeqOrderError):
        cooperative_irl_audit_event("teamed", -1)


# 15. determinism + tamper-as-data + threads + main() subprocess check
def test_determinism_tamper_threads_main():
    def build():
        c = CooperativeIRL()
        c.register_team("t1", 1, human_digest=_digest(b"h"), robot_digest=_digest(b"r"))
        c.interact("t1", 2, role="human", action_kind="demonstration",
                   action_digest=_digest(b"a"))
        c.learn("t1", 3, learning_kind="reward-inference", outcome="improved",
                belief_digest=_digest(b"b"))
        return c

    c1, c2 = build(), build()
    assert c1.interaction_record("int-1", 4).digest == \
        c2.interaction_record("int-1", 4).digest
    assert c1.evaluate("t1", 4).digest == c2.evaluate("t1", 4).digest
    import dataclasses
    rec = c1.interaction_record("int-1", 4)
    tampered = dataclasses.replace(rec, role="robot")
    assert tampered.verify() is False
    object.__setattr__(rec, "role", "robot")
    assert rec.verify() is False
    assert c1.evaluate("t1", 4).integrity_ok is False
    # frozen-ness
    with pytest.raises(Exception):
        rec.role = "human"
    # 8-thread read smoke
    results = []

    def worker():
        results.append(c1.evaluate("t1", 5).posture)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == "cooperative" for r in results)
    # main() subprocess check
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "cooperative-irl OK: register, interact, learn, evaluate, pins, audit"
    )
