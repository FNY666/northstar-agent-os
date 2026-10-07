"""Tests for the active-learning query-acquisition ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "active_learning.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("active_learning", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["active_learning"] = module
    spec.loader.exec_module(module)
    return module


al = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert al.ACTIVE_LEARNING_VERSION == "active-learning.v1"
    assert al.SCHEMA_PIN == "northstar.active-learning.v1"
    assert al.STRATEGIES == (
        "uncertainty-sampling",
        "query-by-committee",
        "expected-model-change",
        "expected-error-reduction",
        "variance-reduction",
        "density-weighted",
        "margin-sampling",
        "entropy-sampling",
    )
    assert al.LEARN_OUTCOMES == (
        "improved",
        "no-change",
        "regressed",
        "inconclusive",
    )
    assert al.RETIRE_REASONS == (
        "manual",
        "budget-exhausted",
        "converged",
        "superseded",
        "decommissioned",
    )
    assert set(al.AUDIT_KINDS) == {
        "queried",
        "learned",
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
            imports.update(n.name.split(".")[0] for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. query roundtrip + verify + frozen-ness
def test_query_roundtrip():
    m = al.ActiveLearning()
    rec = m.query("sys-1", 1, strategy="margin-sampling", candidate_digest=PIN)
    assert rec.query_id == "qry-1"
    assert rec.learner_id == "sys-1"
    assert rec.strategy == "margin-sampling"
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.active-learning.v1"
    with pytest.raises(Exception):
        rec.strategy = "uncertainty-sampling"  # frozen
    assert m.query_record("qry-1", 2) is rec
    assert m.learner_ids(2) == ("sys-1",)


# 4. query bad-input table + seq-burn + rejected-row accounting
def test_query_bad_inputs():
    m = al.ActiveLearning()
    seq = 0
    bad = [
        (lambda s: m.query("", s, candidate_digest=PIN), al.BadIdError),
        (lambda s: m.query("sys", s, strategy="random", candidate_digest=PIN), al.BadStrategyError),
        (lambda s: m.query("sys", s, strategy=None, candidate_digest=PIN), al.BadStrategyError),
        (lambda s: m.query("sys", s, candidate_digest="raw"), al.BadDigestError),
        (lambda s: m.query("sys", s, candidate_digest="md5:abc"), al.BadDigestError),
        (lambda s: m.query("sys", s, candidate_digest=PIN[:20]), al.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert m.stats(seq + 1)["rejected"] == 6
    assert m.stats(seq + 1)["queries"] == 0
    rows = [r for r in m.audit_log(seq + 1) if r["kind"] == "rejected"]
    assert len(rows) == 6
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)
    # retired ids never recycled
    m2 = al.ActiveLearning()
    m2.query("sys-9", 1, candidate_digest=PIN)
    m2.retire("sys-9", 2)
    with pytest.raises(al.RetiredLearnerError):
        m2.query("sys-9", 3, candidate_digest=PIN)
    assert m2.stats(4)["rejected"] == 1


# 5. full strategy vocabulary acceptance
def test_strategy_vocabulary():
    m = al.ActiveLearning()
    seq = 0
    for i, strat in enumerate(al.STRATEGIES):
        seq += 1
        rec = m.query(f"sys-{i}", seq, strategy=strat, candidate_digest=PIN)
        assert rec.verify()
        assert rec.query_id == f"qry-{i + 1}"
    assert m.stats(seq + 1)["queries"] == 8


# 6. learn roundtrip + minted ids + verify
def test_learn_roundtrip():
    m = al.ActiveLearning()
    m.query("sys-1", 1, candidate_digest=PIN)
    lrn = m.learn("qry-1", 2, outcome="improved", label_digest=PIN2)
    assert lrn.learn_id == "lrn-1"
    assert lrn.query_id == "qry-1"
    assert lrn.learner_id == "sys-1"
    assert lrn.outcome == "improved"
    assert lrn.verify()
    assert m.learn_record("lrn-1", 3) is lrn
    assert m.learns_for("sys-1", 3) == ("lrn-1",)


# 7. learn refusal table
def test_learn_refusals():
    m = al.ActiveLearning()
    m.query("sys-1", 1, candidate_digest=PIN)
    m.learn("qry-1", 2, outcome="improved", label_digest=PIN)
    seq = 2
    bad = [
        (lambda s: m.learn("qry-404", s, label_digest=PIN), al.UnknownQueryError),
        (lambda s: m.learn("qry-1", s, label_digest=PIN), al.AlreadyLearnedError),
        (lambda s: m.learn("", s, label_digest=PIN), al.BadIdError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    # bad outcome needs a fresh query
    m.query("sys-1", seq + 1, candidate_digest=PIN)
    seq += 1
    with pytest.raises(al.BadOutcomeError):
        m.learn("qry-2", seq + 1, outcome="magical", label_digest=PIN)
    seq += 1
    with pytest.raises(al.BadDigestError):
        m.learn("qry-2", seq + 1, outcome="improved", label_digest="raw")
    seq += 1
    assert m.stats(seq + 1)["rejected"] == 5
    assert m.stats(seq + 1)["learns"] == 1


# 8. evaluate posture math
def test_evaluate_posture_math():
    m = al.ActiveLearning()
    # untrained: queries booked, no learns
    m.query("s1", 1, candidate_digest=PIN)
    rep = m.evaluate("s1", 2)
    assert rep.posture == "untrained"
    assert rep.verify()
    # improving: all improved
    m.learn("qry-1", 3, outcome="improved", label_digest=PIN)
    assert m.evaluate("s1", 4).posture == "improving"
    # plateaued: improved + no-change
    m.query("s1", 5, candidate_digest=PIN)
    m.learn("qry-2", 6, outcome="no-change", label_digest=PIN)
    assert m.evaluate("s1", 7).posture == "plateaued"
    # regressed wins over plateaued
    m.query("s1", 8, candidate_digest=PIN)
    m.learn("qry-3", 9, outcome="regressed", label_digest=PIN)
    assert m.evaluate("s1", 10).posture == "regressed"
    # inconclusive on a fresh learner
    m.query("s2", 11, candidate_digest=PIN)
    m.learn("qry-4", 12, outcome="inconclusive", label_digest=PIN)
    assert m.evaluate("s2", 13).posture == "inconclusive"
    # unknown learner refused fail-closed
    with pytest.raises(al.UnknownLearnerError):
        m.evaluate("ghost", 14)
    # tallies + integrity
    rep = m.evaluate("s1", 15)
    assert (rep.n_queries, rep.n_learns) == (3, 3)
    assert rep.integrity_ok is True


# 9. evaluate + views are pure reads (no audit rows, seq not consumed)
def test_evaluate_read_purity():
    m = al.ActiveLearning()
    m.query("s1", 1, candidate_digest=PIN)
    m.learn("qry-1", 2, outcome="improved", label_digest=PIN)
    n_audit = len(m.audit_log(3))
    r1 = m.evaluate("s1", 3)
    r2 = m.evaluate("s1", 3)
    assert r1.verify() and r2.verify()
    assert len(m.audit_log(3)) == n_audit  # reads add no rows
    assert m.query_ids(3) == ("qry-1",)
    assert m.learn_ids(3) == ("lrn-1",)
    assert m.queries_for("s1", 3) == ("qry-1",)


# 10. retire terminality + id non-recycling + reads still work
def test_retire_terminality():
    m = al.ActiveLearning()
    m.query("s1", 1, candidate_digest=PIN)
    m.query("s1", 2, candidate_digest=PIN)  # qry-2 stays unlearned
    m.learn("qry-1", 3, outcome="improved", label_digest=PIN)
    rec = m.retire("s1", 4, reason="budget-exhausted")
    assert rec.verify()
    assert m.retired_ids(5) == ("s1",)
    # post-retire mutations refused
    with pytest.raises(al.RetiredLearnerError):
        m.query("s1", 6, candidate_digest=PIN)
    with pytest.raises(al.RetiredLearnerError):
        m.learn("qry-2", 7, label_digest=PIN)
    # id never recycled, reads still work
    with pytest.raises(al.RetiredLearnerError):
        m.retire("s1", 8)
    rep = m.evaluate("s1", 9)
    assert rep.posture == "improving"
    assert rep.verify()
    with pytest.raises(al.BadReasonError):
        m2 = al.ActiveLearning()
        m2.query("s2", 1, candidate_digest=PIN)
        m2.retire("s2", 2, reason="vibes")
    # retired system id in stats
    assert m.stats(10)["retired"] == 1


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    m = al.ActiveLearning()
    m.query("s1", 5, candidate_digest=PIN)
    # rewind raises bare, no rejected row booked
    with pytest.raises(al.SeqOrderError):
        m.query("s2", 5, candidate_digest=PIN)
    assert m.stats(6)["rejected"] == 0
    # malformed seqs raise bare
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(al.SeqOrderError):
            m.query("s2", bad, candidate_digest=PIN)
    assert m.stats(6)["rejected"] == 0
    # failed mutation consumes seq: next valid mutation must use a higher seq
    with pytest.raises(al.BadStrategyError):
        m.query("s2", 7, strategy="nope", candidate_digest=PIN)
    assert m.stats(8)["rejected"] == 1
    with pytest.raises(al.SeqOrderError):
        m.query("s2", 7, candidate_digest=PIN)  # already burned
    m.query("s2", 8, candidate_digest=PIN)
    assert m.learner_ids(9) == ("s1", "s2")


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    m = al.ActiveLearning()
    m.query("s1", 1, strategy="uncertainty-sampling", candidate_digest=PIN)
    m.learn("qry-1", 2, outcome="improved", label_digest=PIN2)
    rows = m.audit_log(3)
    assert [r["kind"] for r in rows] == ["queried", "learned"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in al._BANNED_AUDIT_KEYS
    # banned raw keys are refused at the builder level
    with pytest.raises(al.AuditKindError):
        al.active_learning_audit_event("queried", 1, example="raw text")
    with pytest.raises(al.AuditKindError):
        al.active_learning_audit_event("queried", 1, label="x")
    with pytest.raises(al.AuditKindError):
        al.active_learning_audit_event("bogus-kind", 1)
    with pytest.raises(al.SeqOrderError):
        al.active_learning_audit_event("queried", -1)
    # pinned vocabulary values remain emittable as declared data
    row = al.active_learning_audit_event(
        "queried", 1, strategy="entropy-sampling", outcome="improved"
    )
    assert row["details"]["strategy"] == "entropy-sampling"


# 13. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        g = al.ActiveLearning()
        g.query("s1", 1, strategy="density-weighted", candidate_digest=PIN)
        g.learn("qry-1", 2, outcome="no-change", label_digest=PIN2)
        return g

    g1, g2 = build(), build()
    assert g1.query_record("qry-1", 3).digest == g2.query_record("qry-1", 3).digest
    assert g1.learn_record("lrn-1", 3).digest == g2.learn_record("lrn-1", 3).digest
    # tamper breaks verify and flips integrity_ok as data
    rec = g1.query_record("qry-1", 3)
    object.__setattr__(rec, "strategy", "random")  # type: ignore
    assert rec.verify() is False
    rep = g1.evaluate("s1", 4)
    assert rep.integrity_ok is False
    assert rep.verify() is True  # report itself is consistent


# 14. views / stats / unknown lookups
def test_views_and_stats():
    m = al.ActiveLearning()
    m.query("s1", 1, candidate_digest=PIN)
    m.query("s2", 2, candidate_digest=PIN)
    m.learn("qry-2", 3, outcome="regressed", label_digest=PIN)
    assert m.query_ids(4) == ("qry-1", "qry-2")
    assert m.learn_ids(4) == ("lrn-1",)
    assert m.queries_for("s2", 4) == ("qry-2",)
    assert m.learns_for("s2", 4) == ("lrn-1",)
    assert m.learns_for("s1", 4) == ()
    assert m.retired_ids(4) == ()
    assert m.stats(4) == {
        "learners": 2,
        "queries": 2,
        "learns": 1,
        "retired": 0,
        "rejected": 0,
    }
    with pytest.raises(al.UnknownQueryError):
        m.query_record("qry-404", 5)
    with pytest.raises(al.UnknownQueryError):
        m.learn_record("lrn-404", 5)
    with pytest.raises(al.UnknownLearnerError):
        m.queries_for("ghost", 5)
    with pytest.raises(al.UnknownLearnerError):
        m.learns_for("ghost", 5)


# 15. determinism, frozen-ness, thread smoke, main()
def test_determinism_frozen_and_threads():
    g1 = al.ActiveLearning()
    g2 = al.ActiveLearning()
    for i, g in enumerate((g1, g2), start=1):
        g.query("sys-a", i, strategy="query-by-committee", candidate_digest=PIN)
    assert g1.query_record("qry-1", 3).digest == g2.query_record("qry-1", 3).digest
    # records are frozen
    rec = g1.query_record("qry-1", 4)
    with pytest.raises(Exception):
        rec.strategy = "x"  # type: ignore
    # 8 threads of pure reads with the same seq
    errors = []

    def reader():
        try:
            for _ in range(50):
                g1.evaluate("sys-a", 5)
                g1.query_record("qry-1", 5)
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
    # main() subprocess check
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert (
        "active-learning OK: query, learn, evaluate, retire, pins, audit"
        in proc.stdout
    )
