"""Tests for value_learning (value-learning decision ledger, Simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

import value_learning as vl

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


def _def() -> vl.ValueLearning:
    return vl.ValueLearning()


def _observed(subject: str = "sub-1", seq: int = 1) -> vl.ValueLearning:
    d = _def()
    d.observe(subject, seq, observation_kind="demonstration")
    return d


# 1. version/schema/vocabulary pins
def test_pins():
    assert vl.VALUE_LEARNING_VERSION == "value-learning.v1"
    assert vl.SCHEMA_PIN == "northstar.value-learning.v1"
    assert len(vl.OBSERVATION_KINDS) == 8
    assert "demonstration" in vl.OBSERVATION_KINDS
    assert "cooperation-signal" in vl.OBSERVATION_KINDS
    assert len(vl.INFER_METHODS) == 8
    assert "inverse-rl" in vl.INFER_METHODS
    assert "meta-inference" in vl.INFER_METHODS
    assert len(vl.VALUE_CLAIMS) == 8
    assert "helpfulness" in vl.VALUE_CLAIMS
    assert "care" in vl.VALUE_CLAIMS
    assert vl.VERIFY_VERDICTS == ("consistent", "tampered")
    assert vl.AUDIT_KINDS == ("observed", "inferred", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(open(vl.__file__).read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW


# 3. observe roundtrip + verify + frozen-ness
def test_observe_roundtrip():
    d = _def()
    rec = d.observe(
        "sub-1", 1, observation_kind="stated-value",
        observation_digest=_digest(), context_digest=_digest(b"ctx"),
    )
    assert rec.observation_id == "obs-1"
    assert rec.subject_id == "sub-1"
    assert rec.observation_kind == "stated-value"
    assert rec.verify()
    assert rec.as_dict()["schema"] == vl.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.observation_kind = "feedback"  # frozen


# 4. observe bad-input table + seq-burn + rejected-row accounting
def test_observe_bad_inputs():
    d = _def()
    seq = 0
    bad = [
        (lambda s: d.observe("", s), vl.BadIdError),
        (lambda s: d.observe("x" * 129, s), vl.BadIdError),
        (lambda s: d.observe("sub-1", s, observation_kind="vibes"), vl.BadKindError),
        (lambda s: d.observe("sub-1", s, observation_digest="raw"), vl.BadDigestError),
        (lambda s: d.observe("sub-1", s, context_digest="md5:abc"), vl.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert d.stats(seq + 1)["rejected"] == len(bad)
    # next seq still accepted
    rec = d.observe("sub-1", seq + 2)
    assert rec.observation_id == "obs-1"


# 5. full observation-kind vocabulary acceptance
def test_all_observation_kinds():
    d = _def()
    for i, kind in enumerate(vl.OBSERVATION_KINDS, start=1):
        rec = d.observe("sub-1", i, observation_kind=kind)
        assert rec.verify()
    assert len(d.observation_ids(100)) == len(vl.OBSERVATION_KINDS)


# 6. infer roundtrip + minted ids + verify
def test_infer_roundtrip():
    d = _observed()
    rec = d.infer(
        "sub-1", 2, method="bayesian-irl", value_claim="harmlessness",
        confidence=73, evidence_digest=_digest(),
    )
    assert rec.inference_id == "inf-1"
    assert rec.subject_id == "sub-1"
    assert rec.method == "bayesian-irl"
    assert rec.value_claim == "harmlessness"
    assert rec.confidence == 73
    assert rec.verify()
    assert rec.as_dict()["schema"] == vl.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.confidence = 99  # frozen


# 7. infer refusals: unknown subject, no observations, bad inputs + seq-burn
def test_infer_refusals():
    d = _def()
    with pytest.raises(vl.NoObservationError):
        d.infer("ghost", 1)  # consumes seq 1
    with pytest.raises(vl.SeqOrderError):
        d.infer("ghost", 1)  # rewind: bare, no new row
    assert d.stats(2)["rejected"] == 1
    d.observe("sub-1", 3)
    bad = [
        (lambda s: d.infer("sub-1", s, method="guesswork"), vl.BadMethodError),
        (lambda s: d.infer("sub-1", s, value_claim="money"), vl.BadClaimError),
        (lambda s: d.infer("sub-1", s, confidence=101), vl.BadConfidenceError),
        (lambda s: d.infer("sub-1", s, confidence=-1), vl.BadConfidenceError),
        (lambda s: d.infer("sub-1", s, confidence=True), vl.BadConfidenceError),
        (lambda s: d.infer("sub-1", s, evidence_digest="nope"), vl.BadDigestError),
    ]
    seq = 3
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert d.stats(seq + 1)["rejected"] == 1 + len(bad)


# 8. full infer-method x value-claim vocabulary acceptance
def test_infer_vocabulary():
    d = _observed()
    seq = 1
    for method in vl.INFER_METHODS:
        for claim in vl.VALUE_CLAIMS:
            seq += 1
            rec = d.infer("sub-1", seq, method=method, value_claim=claim)
            assert rec.verify()
    assert d.stats(seq + 1)["inferences"] == (
        len(vl.INFER_METHODS) * len(vl.VALUE_CLAIMS)
    )


# 9. verify roundtrip + read purity + unknown refusal
def test_verify_roundtrip():
    d = _observed()
    d.infer("sub-1", 2, value_claim="honesty", confidence=50)
    n_audit = len(d.audit_log(3))
    rep = d.verify("inf-1", 3)
    assert rep.verdict == "consistent"
    assert rep.integrity_ok
    assert rep.verify()
    assert rep.as_dict()["schema"] == vl.SCHEMA_PIN
    # reads consume nothing, write no rows
    rep2 = d.verify("inf-1", 3)
    assert rep2.verdict == "consistent"
    assert len(d.audit_log(3)) == n_audit
    with pytest.raises(vl.UnknownInferenceError):
        d.verify("inf-9", 4)


# 10. tamper -> tampered verdict as data
def test_verify_tamper():
    d = _observed()
    rec = d.infer("sub-1", 2, value_claim="care")
    object.__setattr__(rec, "confidence", 100)
    rep = d.verify("inf-1", 3)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    d = _def()
    with pytest.raises(vl.SeqOrderError):
        d.observe("sub-1", 0)
    with pytest.raises(vl.SeqOrderError):
        d.observe("sub-1", -1)
    for bad in (True, 1.5, "2", None):
        with pytest.raises(vl.SeqOrderError):
            d.observe("sub-1", bad)
    d.observe("sub-1", 5)
    with pytest.raises(vl.SeqOrderError):
        d.observe("sub-2", 5)  # rewind: bare
    assert d.stats(6)["rejected"] == 0  # bare rewinds book no row
    with pytest.raises(vl.BadKindError):
        d.observe("sub-2", 7, observation_kind="nope")  # burns seq 7
    rec = d.observe("sub-2", 8)
    assert rec.observation_id == "obs-2"


# 12. view read-purity: same-seq twice, no audit rows, unknown lookups
def test_view_read_purity():
    d = _observed()
    d.infer("sub-1", 2, value_claim="fairness")
    n_audit = len(d.audit_log(3))
    assert d.subject_ids(3) == ("sub-1",)
    assert d.observation_ids(3) == ("obs-1",)
    assert d.inference_ids(3) == ("inf-1",)
    assert d.observations_for("sub-1", 3) == ("obs-1",)
    assert d.inferences_for("sub-1", 3) == ("inf-1",)
    assert d.inferences_for("sub-2", 3) == ()
    assert d.observation_record("obs-1", 3).verify()
    assert d.inference_record("inf-1", 3).verify()
    assert len(d.audit_log(3)) == n_audit
    with pytest.raises(vl.UnknownObservationError):
        d.observation_record("obs-9", 4)
    with pytest.raises(vl.UnknownInferenceError):
        d.inference_record("inf-9", 4)
    with pytest.raises(vl.UnknownSubjectError):
        d.observations_for("ghost", 4)


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    d = _observed()
    d.infer("sub-1", 2, value_claim="obedience")
    rows = d.audit_log(3)
    assert [r["kind"] for r in rows] == ["observed", "inferred"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in vl._BANNED_AUDIT_KEYS
    with pytest.raises(vl.AuditKindError):
        vl.value_learning_audit_event("observed", 1, behavior="alice")
    with pytest.raises(vl.AuditKindError):
        vl.value_learning_audit_event("bogus-kind", 1)
    with pytest.raises(vl.SeqOrderError):
        vl.value_learning_audit_event("observed", -1)


# 14. cross-instance digest determinism + frozen-ness + 8-thread read smoke
def test_determinism_and_concurrency():
    def build():
        d = vl.ValueLearning()
        d.observe("sub-1", 1, observation_kind="feedback",
                  observation_digest=_digest())
        d.infer("sub-1", 2, method="preference-inference",
                value_claim="autonomy", confidence=42)
        return d

    d1, d2 = build(), build()
    assert d1.observation_record("obs-1", 3).digest == (
        d2.observation_record("obs-1", 3).digest
    )
    assert d1.inference_record("inf-1", 3).digest == (
        d2.inference_record("inf-1", 3).digest
    )
    results = []

    def worker():
        results.append(d1.subject_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == ("sub-1",) for r in results)
    rec = d1.inference_record("inf-1", 100)
    with pytest.raises(Exception):
        rec.method = "inverse-rl"  # frozen


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, "value_learning.py"],
        capture_output=True,
        text=True,
        cwd=str(vl.__file__.rsplit("/", 1)[0]),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "value-learning OK: observe, infer, verify, pins, audit"
    )
