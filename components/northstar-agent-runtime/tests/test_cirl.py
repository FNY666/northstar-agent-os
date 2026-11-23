"""Tests for cirl (Cooperative Inverse Reinforcement Learning ledger, Simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

from cirl import (
    CIRL_VERSION,
    SCHEMA_PIN,
    INTERACTION_KINDS,
    LEARN_METHODS,
    BELIEF_OUTCOMES,
    POSTURES,
    AUDIT_KINDS,
    CIIRError,
    BadIdError,
    BadDigestError,
    BadKindError,
    BadMethodError,
    BadOutcomeError,
    UnknownAgentError,
    UnknownInteractionError,
    SeqOrderError,
    AuditKindError,
    InteractionRecord,
    LearningRecord,
    EvaluationReport,
    CIRL,
    cirl_audit_event,
)

MOD = None
import cirl as _mod

MOD = _mod.__file__

STDLIB_ALLOW = {
    "hashlib",
    "json",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "canonical_json",
}


def _digest(tag: bytes = b"content") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _cirl() -> CIRL:
    return CIRL()


# 1. version/schema/vocabulary pins
def test_pins():
    assert CIRL_VERSION == "cirl.v1"
    assert SCHEMA_PIN == "northstar.cirl.v1"
    assert INTERACTION_KINDS == (
        "demonstration",
        "comparison",
        "correction",
        "instruction",
        "query-response",
        "approval",
        "oversight-check",
        "shutdown-acceptance",
    )
    assert LEARN_METHODS == (
        "irl",
        "preference-learning",
        "demonstration-learning",
        "correction-learning",
        "active-learning",
        "offline-cirl",
        "interactive-cirl",
        "cooperative-inference",
    )
    assert BELIEF_OUTCOMES == (
        "confident",
        "uncertain",
        "conflicted",
        "unknown",
    )
    assert POSTURES == (
        "unevaluated",
        "uninformed",
        "conflicted",
        "unknown",
        "uncertain",
        "confident-learning",
    )
    assert AUDIT_KINDS == ("interacted", "learned", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(open(_mod.__file__).read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW


# 3. interact roundtrip + verify + frozen-ness
def test_interact_roundtrip():
    c = _cirl()
    rec = c.interact(
        "a-1", 1, kind="demonstration", interaction_digest=_digest()
    )
    assert rec.interaction_id == "int-1"
    assert rec.agent_id == "a-1"
    assert rec.kind == "demonstration"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.kind = "comparison"  # frozen
    assert c.agent_ids(2) == ("a-1",)


# 4. interact bad-input table + seq-burn + rejected rows
def test_interact_bad_inputs():
    c = _cirl()
    seq = 0
    bad = [
        (lambda s: c.interact("", s), BadIdError),
        (lambda s: c.interact(123, s), BadIdError),
        (lambda s: c.interact("a-1", s, kind="mind-meld"), BadKindError),
        (lambda s: c.interact("a-1", s, interaction_digest="raw"), BadDigestError),
        (lambda s: c.interact("a-1", s, interaction_digest="md5:abc"), BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert c.stats(100)["rejected"] == len(bad)
    # failed mutations consumed their seqs: next mutation must use seq+1
    c.interact("a-1", seq + 1)
    assert c.stats(100)["interactions"] == 1


# 5. full interaction-kind vocabulary acceptance
def test_interaction_kind_vocabulary():
    c = _cirl()
    for i, kind in enumerate(INTERACTION_KINDS, start=1):
        rec = c.interact("a-1", i, kind=kind)
        assert rec.kind == kind
        assert rec.verify()
    assert c.stats(100)["interactions"] == len(INTERACTION_KINDS)


# 6. learn roundtrip + minted ids + verify
def test_learn_roundtrip():
    c = _cirl()
    c.interact("a-1", 1)
    rec = c.learn(
        "a-1", 2, method="irl", belief_outcome="confident",
        belief_digest=_digest(b"belief"),
    )
    assert rec.learning_id == "lrn-1"
    assert rec.agent_id == "a-1"
    assert rec.method == "irl"
    assert rec.belief_outcome == "confident"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.belief_outcome = "uncertain"  # frozen


# 7. learn bad-input table + unknown-agent refusal
def test_learn_bad_inputs():
    c = _cirl()
    c.interact("a-1", 1)
    seq = 1
    bad = [
        (lambda s: c.learn("", s), BadIdError),
        (lambda s: c.learn("a-1", s, method="mind-meld"), BadMethodError),
        (lambda s: c.learn("a-1", s, belief_outcome="vibes"), BadOutcomeError),
        (lambda s: c.learn("a-1", s, belief_digest="raw"), BadDigestError),
        (lambda s: c.learn("ghost", s), UnknownAgentError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert c.stats(100)["rejected"] == len(bad)


# 8. full method x outcome vocabulary acceptance
def test_learn_method_outcome_vocabulary():
    c = _cirl()
    c.interact("a-1", 1)
    seq = 1
    for method in LEARN_METHODS:
        for outcome in BELIEF_OUTCOMES:
            seq += 1
            rec = c.learn("a-1", seq, method=method, belief_outcome=outcome)
            assert rec.verify()
    assert c.stats(100)["learnings"] == len(LEARN_METHODS) * len(BELIEF_OUTCOMES)


# 9. evaluate posture math across all postures
def test_evaluate_postures():
    c = _cirl()
    # unevaluated: registered? evaluate raises for unknown agents;
    # book an interaction first to register, then a second agent stays
    # unevaluated... actually unregistered agents refuse, so unevaluated is
    # unreachable via a bare agent id; instead check the rest.
    c.interact("u1", 1)  # uninformed
    assert c.evaluate("u1", 2).posture == "uninformed"
    c.interact("c1", 3)
    c.learn("c1", 4, belief_outcome="conflicted")  # conflicted
    c.learn("c1", 5, belief_outcome="confident")
    assert c.evaluate("c1", 6).posture == "conflicted"
    c.interact("k1", 7)
    c.learn("k1", 8, belief_outcome="unknown")  # unknown
    c.learn("k1", 9, belief_outcome="confident")
    assert c.evaluate("k1", 10).posture == "unknown"
    c.interact("f1", 11)
    c.learn("f1", 12, belief_outcome="confident")  # confident-learning
    c.learn("f1", 13, belief_outcome="confident")
    assert c.evaluate("f1", 14).posture == "confident-learning"
    c.interact("x1", 15)
    c.learn("x1", 16, belief_outcome="uncertain")  # uncertain
    assert c.evaluate("x1", 17).posture == "uncertain"
    r = c.evaluate("f1", 18)
    assert r.n_interactions == 1
    assert r.n_learnings == 2
    assert r.integrity_ok is True
    assert r.verify()
    assert r.as_dict()["schema"] == SCHEMA_PIN


# 10. evaluate unknown-agent refusal + read purity
def test_evaluate_refusal_and_read_purity():
    c = _cirl()
    with pytest.raises(UnknownAgentError):
        c.evaluate("ghost", 1)  # unknown agent refuses; seq not consumed
    c.interact("a-1", 1)
    n_audit = len(c.audit_log(2))
    r1 = c.evaluate("a-1", 2)
    r2 = c.evaluate("a-1", 2)  # same seq twice: reads are pure
    assert r1.verify() and r2.verify()
    assert len(c.audit_log(2)) == n_audit  # reads add no rows


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes
def test_seq_discipline():
    c = _cirl()
    c.interact("a-1", 5, kind="demonstration")
    with pytest.raises(SeqOrderError):
        c.interact("a-2", 5)  # rewind: bare, no rejected row
    assert c.stats(100)["rejected"] == 0
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            c.interact("a-2", bad)
    # failed mutation consumes seq + books rejected row
    with pytest.raises(BadKindError):
        c.interact("a-2", 6, kind="nope")
    assert c.stats(100)["rejected"] == 1
    c.interact("a-2", 7)  # must continue from consumed seq
    assert c.stats(100)["interactions"] == 2


# 12. views read purity + stats + unknown lookups
def test_views_and_stats():
    c = _cirl()
    c.interact("a-1", 1, kind="comparison")
    c.learn("a-1", 2, method="preference-learning", belief_outcome="uncertain")
    assert c.interaction_ids(3) == ("int-1",)
    assert c.learning_ids(3) == ("lrn-1",)
    assert c.interactions_for("a-1", 3) == ("int-1",)
    assert c.learnings_for("a-1", 3) == ("lrn-1",)
    assert c.interaction_record("int-1", 3).verify()
    assert c.learning_record("lrn-1", 3).verify()
    assert c.stats(3) == {
        "agents": 1,
        "interactions": 1,
        "learnings": 1,
        "rejected": 0,
    }
    with pytest.raises(UnknownInteractionError):
        c.interaction_record("int-9", 3)
    with pytest.raises(UnknownInteractionError):
        c.learning_record("lrn-9", 3)
    with pytest.raises(UnknownAgentError):
        c.interactions_for("ghost", 3)


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    c = _cirl()
    c.interact("a-1", 1, kind="correction", interaction_digest=_digest())
    c.learn("a-1", 2, method="correction-learning")
    rows = c.audit_log(3)
    assert [r["kind"] for r in rows] == ["interacted", "learned"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in _mod._BANNED_AUDIT_KEYS
    with pytest.raises(AuditKindError):
        cirl_audit_event("interacted", 1, trajectory="raw-text")
    with pytest.raises(AuditKindError):
        cirl_audit_event("bogus-kind", 1)
    with pytest.raises(SeqOrderError):
        cirl_audit_event("interacted", -1)


# 14. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        c = CIRL()
        c.interact("a-1", 1, kind="query-response", interaction_digest=_digest())
        c.learn("a-1", 2, method="active-learning", belief_outcome="uncertain")
        return c

    c1, c2 = build(), build()
    assert c1.interaction_record("int-1", 3).digest == (
        c2.interaction_record("int-1", 3).digest
    )
    assert c1.learning_record("lrn-1", 3).digest == (
        c2.learning_record("lrn-1", 3).digest
    )
    import dataclasses

    rec = c1.learning_record("lrn-1", 3)
    tampered = dataclasses.replace(rec, belief_outcome="confident")
    assert tampered.verify() is False
    object.__setattr__(rec, "belief_outcome", "confident")
    assert rec.verify() is False
    assert c1.evaluate("a-1", 3).integrity_ok is False


# 15. main() subprocess check + 8-thread read smoke
def test_main_and_concurrency():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(_mod.__file__.rsplit("/", 1)[0]),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "cirl OK: interact, learn, evaluate, pins, audit"

    c = _cirl()
    for i in range(10):
        aid = f"a{i}"
        c.interact(aid, i * 3 + 1, kind="oversight-check")
        c.learn(aid, i * 3 + 2, method="interactive-cirl")
    results = []

    def worker():
        results.append(c.agent_ids(100))
        results.append(c.evaluate("a0", 101).posture)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results[::2])
    assert all(r == "uncertain" for r in results[1::2])
