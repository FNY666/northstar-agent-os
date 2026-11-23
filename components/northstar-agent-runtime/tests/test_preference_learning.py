"""Tests for preference_learning (preference learning decision ledger, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import preference_learning as pl
from preference_learning import (
    PREFERENCE_LEARNING_VERSION,
    SCHEMA_PIN,
    COLLECTION_SOURCES,
    TRAIN_METHODS,
    POSTURES,
    RETIRE_REASONS,
    AUDIT_KINDS,
    PreferenceLearning,
    preference_learning_audit_event,
)

MOD = Path(pl.__file__)

STDLIB_ALLOW = {
    "hashlib", "json", "threading", "dataclasses", "typing", "__future__",
    "canonical_json",
}


def _digest(tag: bytes = b"feedback") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _led() -> PreferenceLearning:
    return PreferenceLearning()


# 1. version/schema/vocabulary pins
def test_pins():
    assert PREFERENCE_LEARNING_VERSION == "preference-learning.v1"
    assert SCHEMA_PIN == "northstar.preference-learning.v1"
    assert len(COLLECTION_SOURCES) == 5 and "human" in COLLECTION_SOURCES
    assert len(TRAIN_METHODS) == 6 and "dpo" in TRAIN_METHODS
    assert len(POSTURES) == 2 and "trained" in POSTURES
    assert len(RETIRE_REASONS) == 4 and "training-complete" in RETIRE_REASONS
    assert set(AUDIT_KINDS) == {"collected", "trained", "retired", "rejected"}


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


# 3. collect roundtrip + verify + frozen-ness
def test_collect_roundtrip():
    p = _led()
    rec = p.collect("s1", 1, source="expert", n_pairs=40,
                    feedback_digest=_digest())
    assert rec.collection_id == "col-1"
    assert rec.system_id == "s1"
    assert rec.source == "expert"
    assert rec.n_pairs == 40
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.source = "crowd"  # frozen


# 4. collect bad-input table + seq-burn + rejected-row accounting
def test_collect_bad_inputs():
    p = _led()
    seq = 0
    bad = [
        (lambda q: p.collect("", q), pl.BadIdError),
        (lambda q: p.collect(123, q), pl.BadIdError),
        (lambda q: p.collect("s1", q, source="mind-reading"), pl.BadSourceError),
        (lambda q: p.collect("s1", q, n_pairs=-1), pl.BadCountError),
        (lambda q: p.collect("s1", q, n_pairs=True), pl.BadCountError),
        (lambda q: p.collect("s1", q, n_pairs=1.5), pl.BadCountError),
        (lambda q: p.collect("s1", q, feedback_digest="raw"), pl.BadDigestError),
        (lambda q: p.collect("s1", q, feedback_digest="md5:abc"), pl.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert p.stats(seq + 1)["rejected"] == len(bad)
    assert p.stats(seq + 1)["collections"] == 0


# 5. full collection-source vocabulary acceptance
def test_full_source_vocabulary():
    p = _led()
    seq = 0
    for i, source in enumerate(COLLECTION_SOURCES):
        seq += 1
        rec = p.collect("s1", seq, source=source, n_pairs=i)
        assert rec.source == source
        assert rec.verify()
    assert p.collections_for("s1", seq + 1) == tuple(f"col-{i + 1}" for i in range(len(COLLECTION_SOURCES)))


# 6. train roundtrip + minted ids + verify
def test_train_roundtrip():
    p = _led()
    p.collect("s1", 1, n_pairs=10)
    rec = p.train("s1", 2, method="bradley-terry", train_digest=_digest())
    assert rec.train_id == "trn-1"
    assert rec.system_id == "s1"
    assert rec.method == "bradley-terry"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.method = "dpo"  # frozen


# 7. train bad-input table + no-collection refusal + seq-burn
def test_train_bad_inputs():
    p = _led()
    p.collect("s1", 1)
    seq = 1
    bad = [
        (lambda q: p.train("", q), pl.BadIdError),
        (lambda q: p.train("s1", q, method="vibes"), pl.BadMethodError),
        (lambda q: p.train("s1", q, train_digest="raw"), pl.BadDigestError),
        (lambda q: p.train("ghost", q), pl.NoCollectionError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert p.stats(seq + 1)["rejected"] == len(bad)
    assert p.stats(seq + 1)["trains"] == 0


# 8. full train-method vocabulary acceptance
def test_full_method_vocabulary():
    p = _led()
    p.collect("s1", 1)
    seq = 1
    for method in TRAIN_METHODS:
        seq += 1
        rec = p.train("s1", seq, method=method)
        assert rec.method == method
        assert rec.verify()
    assert p.trains_for("s1", seq + 1) == tuple(f"trn-{i + 1}" for i in range(len(TRAIN_METHODS)))


# 9. evaluate posture math: collected -> trained + unknown refusal
def test_evaluate_postures():
    p = _led()
    p.collect("s1", 1, n_pairs=25)
    p.collect("s1", 2, n_pairs=25)
    rep = p.evaluate("s1", 3)
    assert rep.posture == "collected"
    assert rep.n_collections == 2
    assert rep.n_trains == 0
    assert rep.total_pairs == 50
    assert rep.integrity_ok
    assert rep.verify()
    p.train("s1", 4, method="kto")
    rep2 = p.evaluate("s1", 5)
    assert rep2.posture == "trained"
    assert rep2.n_trains == 1
    assert rep2.verify()
    with pytest.raises(pl.UnknownSystemError):
        p.evaluate("ghost", 6)


# 10. evaluate read purity: same seq twice, no audit rows
def test_evaluate_read_purity():
    p = _led()
    p.collect("s1", 1)
    n_audit = len(p.audit_log(2))
    r1 = p.evaluate("s1", 3)
    r2 = p.evaluate("s1", 3)
    assert r1.verify() and r2.verify()
    assert len(p.audit_log(3)) == n_audit  # reads add no rows
    assert p.system_ids(3) == ("s1",)


# 11. retire terminality + id non-recycling + bad reason + reads still work
def test_retire_terminality():
    p = _led()
    p.collect("s1", 1)
    p.retire("s1", 2, reason="training-complete")
    with pytest.raises(pl.RetiredSystemError):
        p.collect("s1", 3)  # retired id never recycled
    with pytest.raises(pl.RetiredSystemError):
        p.train("s1", 4)
    with pytest.raises(pl.RetiredSystemError):
        p.retire("s1", 5)  # double retire refused
    # reads still work post-retire
    assert p.evaluate("s1", 6).posture == "collected"
    p.collect("s2", 7)
    with pytest.raises(pl.BadReasonError):
        p.retire("s2", 8, reason="vibes")


# 12. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    p = _led()
    p.collect("s1", 5)
    with pytest.raises(pl.SeqOrderError):
        p.collect("s2", 5)  # rewind: bare
    assert p.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(pl.SeqOrderError):
            p.collect("s2", bad)
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(pl.BadSourceError):
        p.collect("s1", 7, source="vibes")
    assert p.stats(8)["rejected"] == 1
    p.collect("s2", 9)
    assert p.system_ids(10) == ("s1", "s2")


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    p = _led()
    p.collect("s1", 1, source="human", n_pairs=3)
    p.train("s1", 2, method="ppo")
    p.retire("s1", 3)
    rows = p.audit_log(4)
    assert [r["kind"] for r in rows] == ["collected", "trained", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in pl._BANNED_AUDIT_KEYS
    with pytest.raises(pl.AuditKindError):
        pl.preference_learning_audit_event("collected", 1, prompt="x")
    with pytest.raises(pl.AuditKindError):
        pl.preference_learning_audit_event("bogus-kind", 1)
    with pytest.raises(pl.SeqOrderError):
        pl.preference_learning_audit_event("collected", -1)


# 14. cross-instance digest determinism + tamper breaks verify + integrity flips
def test_determinism_and_tamper():
    def build():
        p = pl.PreferenceLearning()
        p.collect("s1", 1, source="crowd", n_pairs=7)
        p.train("s1", 2, method="ipo")
        return p

    p1, p2 = build(), build()
    assert p1.collection_record("col-1", 3).digest == p2.collection_record("col-1", 3).digest
    assert p1.train_record("trn-1", 3).digest == p2.train_record("trn-1", 3).digest
    import dataclasses

    rec = p1.collection_record("col-1", 3)
    tampered = dataclasses.replace(rec, n_pairs=999)
    assert tampered.verify() is False
    assert p1.evaluate("s1", 4).integrity_ok is True
    object.__setattr__(rec, "n_pairs", 999)
    assert rec.verify() is False
    assert p1.evaluate("s1", 4).integrity_ok is False


# 15. main() subprocess check + concurrency smoke + frozen-ness
def test_main_self_check_and_concurrency():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "preference-learning OK: collect, train, evaluate, retire, pins, audit"
    )
    p = _led()
    p.collect("s1", 1, n_pairs=5)
    results = []

    def worker():
        results.append(p.system_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == ("s1",) for r in results)
    rec = p.collection_record("col-1", 100)
    with pytest.raises(Exception):
        rec.n_pairs = 0  # frozen
    assert rec.verify()
