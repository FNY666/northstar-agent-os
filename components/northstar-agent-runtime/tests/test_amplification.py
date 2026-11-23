"""Tests for amplification (amplification / distillation decision ledger, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import amplification as am
from amplification import (
    AMPLIFICATION_VERSION,
    SCHEMA_PIN,
    AMPLIFICATION_STRATEGIES,
    DISTILLATION_METHODS,
    AMPLIFY_OUTCOMES,
    DISTILL_OUTCOMES,
    VERIFICATION_VERDICTS,
    TASK_POSTURES,
    RETIRE_REASONS,
    AUDIT_KINDS,
    Amplification,
    amplification_audit_event,
)

MOD = Path(am.__file__)

STDLIB_ALLOW = {
    "hashlib", "json", "threading", "dataclasses", "typing", "__future__",
    "canonical_json",
}


def _digest(tag: bytes = b"amp") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _led() -> Amplification:
    return Amplification()


# 1. version/schema/vocabulary pins
def test_pins():
    assert AMPLIFICATION_VERSION == "amplification.v1"
    assert SCHEMA_PIN == "northstar.amplification.v1"
    assert len(AMPLIFICATION_STRATEGIES) == 8
    assert "task-decomposition" in AMPLIFICATION_STRATEGIES
    assert "debate" in AMPLIFICATION_STRATEGIES
    assert len(DISTILLATION_METHODS) == 8
    assert "behavioral-cloning" in DISTILLATION_METHODS
    assert "rl-distillation" in DISTILLATION_METHODS
    assert len(AMPLIFY_OUTCOMES) == 4 and "aligned" in AMPLIFY_OUTCOMES
    assert len(DISTILL_OUTCOMES) == 4 and "faithful" in DISTILL_OUTCOMES
    assert set(VERIFICATION_VERDICTS) == {"verified", "tampered"}
    assert len(TASK_POSTURES) == 5 and "distilled" in TASK_POSTURES
    assert len(RETIRE_REASONS) == 4 and "cycle-complete" in RETIRE_REASONS
    assert set(AUDIT_KINDS) == {"amplified", "distilled", "retired", "rejected"}


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


# 3. amplify roundtrip + verify + frozen-ness
def test_amplify_roundtrip():
    a = _led()
    rec = a.amplify("t1", 1, strategy="debate", outcome="aligned",
                    overseer_digest=_digest(), task_digest=_digest(b"task"))
    assert rec.amplification_id == "amp-1"
    assert rec.task_id == "t1"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.outcome = "misaligned"  # frozen


# 4. amplify bad-input table + seq-burn + rejected-row accounting
def test_amplify_bad_inputs():
    a = _led()
    seq = 0
    bad = [
        (lambda q: a.amplify("", q), am.BadIdError),
        (lambda q: a.amplify(123, q), am.BadIdError),
        (lambda q: a.amplify("t1", q, strategy="mind-meld"), am.BadStrategyError),
        (lambda q: a.amplify("t1", q, outcome="superb"), am.BadOutcomeError),
        (lambda q: a.amplify("t1", q, overseer_digest="raw"), am.BadDigestError),
        (lambda q: a.amplify("t1", q, overseer_digest="md5:abc"), am.BadDigestError),
        (lambda q: a.amplify("t1", q, task_digest="nonsense"), am.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert a.stats(seq + 1)["rejected"] == len(bad)
    assert a.stats(seq + 1)["runs"] == 0


# 5. full amplification-strategy vocabulary acceptance
def test_full_strategy_vocabulary():
    a = _led()
    seq = 0
    for i, strategy in enumerate(AMPLIFICATION_STRATEGIES):
        seq += 1
        rec = a.amplify("t1", seq, strategy=strategy, outcome="aligned")
        assert rec.strategy == strategy
    assert a.stats(seq + 1)["runs"] == len(AMPLIFICATION_STRATEGIES)
    assert a.amplifications_for("t1", seq + 1) == tuple(
        f"amp-{i + 1}" for i in range(len(AMPLIFICATION_STRATEGIES)))


# 6. distill roundtrip + minted ids + full method vocabulary
def test_distill_roundtrip():
    a = _led()
    run = a.amplify("t1", 1, strategy="task-decomposition", outcome="aligned")
    seq = 1
    for i, method in enumerate(DISTILLATION_METHODS):
        seq += 1
        rec = a.distill(run.amplification_id, f"m-{i}", seq, method=method,
                        outcome="faithful", source_digest=_digest())
        assert rec.distillation_id == f"dst-{i + 1}"
        assert rec.method == method
        assert rec.verify()
    assert a.stats(seq + 1)["distillations"] == len(DISTILLATION_METHODS)
    assert a.distillations_for(run.amplification_id, seq + 1) == tuple(
        f"dst-{i + 1}" for i in range(len(DISTILLATION_METHODS)))


# 7. distill refusals: unknown amplification / bad method / bad outcome / retired
def test_distill_refusals():
    a = _led()
    run = a.amplify("t1", 1, outcome="aligned")
    seq = 1
    bad = [
        (lambda q: a.distill("amp-999", "m1", q), am.UnknownAmplificationError),
        (lambda q: a.distill(run.amplification_id, "m1", q, method="osmiosis"),
         am.BadMethodError),
        (lambda q: a.distill(run.amplification_id, "m1", q, outcome="perfect"),
         am.BadOutcomeError),
        (lambda q: a.distill("", "m1", q), am.BadIdError),
        (lambda q: a.distill(run.amplification_id, "m1", q,
                             source_digest="raw"), am.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    # retire then distill: refused fail-closed
    seq += 1
    a.retire("t1", seq, reason="cycle-complete")
    with pytest.raises(am.RetiredTaskError):
        a.distill(run.amplification_id, "m1", seq + 1)
    assert a.stats(seq + 2)["rejected"] == len(bad) + 1


# 8. verify semantics: verified as data, tamper as data, unknown refused
def test_verify_semantics():
    a = _led()
    run = a.amplify("t1", 1, outcome="aligned")
    dst = a.distill(run.amplification_id, "m1", 2, outcome="faithful")
    rep = a.verify(run.amplification_id, 3)
    assert rep.record_kind == "amplification"
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    rep2 = a.verify(dst.distillation_id, 4)
    assert rep2.record_kind == "distillation"
    assert rep2.verdict == "verified"
    with pytest.raises(am.UnknownRecordError):
        a.verify("amp-999", 5)
    with pytest.raises(am.UnknownRecordError):
        a.verify("dst-999", 6)
    with pytest.raises(am.BadIdError):
        a.verify("", 7)


# 9. verify read purity: same-seq twice, no audit rows, no seq consumption
def test_verify_read_purity():
    a = _led()
    run = a.amplify("t1", 1, outcome="aligned")
    n_audit = len(a.audit_log(2))
    r1 = a.verify(run.amplification_id, 2)
    r2 = a.verify(run.amplification_id, 2)
    assert r1.verify() and r2.verify()
    assert len(a.audit_log(2)) == n_audit  # reads add no rows
    assert a.stats(2)["rejected"] == 0


# 10. retire terminality + id non-recycling + bad reason + reads still work
def test_retire_terminality():
    a = _led()
    run = a.amplify("t1", 1, outcome="aligned")
    a.distill(run.amplification_id, "m1", 2, outcome="faithful")
    rec = a.retire("t1", 3, reason="cycle-complete")
    assert rec.task_id == "t1"
    assert rec.verify()
    assert a.retired_ids(4) == ("t1",)
    # post-retire mutations refused
    with pytest.raises(am.RetiredTaskError):
        a.amplify("t1", 5)
    with pytest.raises(am.RetiredTaskError):
        a.distill(run.amplification_id, "m2", 6)
    # ids never recycled: double retire refused (already retired, not unknown)
    with pytest.raises(am.RetiredTaskError):
        a.retire("t1", 7)
    # reads still work
    assert a.status("t1", 8).posture == "distilled"
    assert a.verify(run.amplification_id, 9).verdict == "verified"
    # bad reason on a live task burns the seq
    a.amplify("t2", 10, outcome="aligned")
    with pytest.raises(am.BadReasonError):
        a.retire("t2", 11, reason="vibes")
    assert a.stats(12)["rejected"] >= 3


# 11. seq discipline: rewind bare (zero rows), malformed seqs, burn on failure
def test_seq_discipline():
    a = _led()
    a.amplify("t1", 1, outcome="aligned")
    # rewind: bare raise, no rejected row
    with pytest.raises(am.SeqOrderError):
        a.amplify("t2", 1)
    assert a.stats(2)["rejected"] == 0
    # malformed seqs
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(am.SeqOrderError):
            a.amplify("t2", bad)
    # failed mutation consumes its seq: next valid seq must be 3
    with pytest.raises(am.BadStrategyError):
        a.amplify("t2", 2, strategy="mind-meld")
    assert a.stats(3)["rejected"] == 1
    rec = a.amplify("t2", 3, outcome="aligned")
    assert rec.amplification_id == "amp-2"
    # reads validate shape without consuming: same seq twice is fine
    assert a.task_ids(4) == ("t1", "t2")
    assert a.task_ids(4) == ("t1", "t2")


# 12. status posture math: not-run / amplified / inconclusive / suspect / distilled
def test_status_posture_math():
    a = _led()
    a.amplify("t1", 1, outcome="not-run")
    assert a.status("t1", 2).posture == "not-run"
    a.amplify("t2", 3, outcome="aligned")
    a.amplify("t2", 4, outcome="aligned")
    assert a.status("t2", 5).posture == "amplified"
    a.amplify("t3", 6, outcome="aligned")
    a.amplify("t3", 7, outcome="inconclusive")
    assert a.status("t3", 8).posture == "inconclusive"
    a.amplify("t4", 9, outcome="aligned")
    a.amplify("t4", 10, outcome="misaligned")
    assert a.status("t4", 11).posture == "suspect"
    run = a.amplify("t5", 12, outcome="aligned")
    a.distill(run.amplification_id, "m1", 13, outcome="lossy")
    st = a.status("t5", 14)
    assert st.posture == "distilled"
    assert st.n_runs == 1 and st.n_distillations == 1
    assert st.integrity_ok is True
    with pytest.raises(am.UnknownTaskError):
        a.status("ghost", 15)


# 13. views and stats counters
def test_views_and_stats():
    a = _led()
    r1 = a.amplify("t1", 1, outcome="aligned")
    a.amplify("t1", 2, outcome="inconclusive")
    d1 = a.distill(r1.amplification_id, "m1", 3, outcome="faithful")
    assert a.amplification_record("amp-1", 4).verify()
    assert a.distillation_record("dst-1", 5).verify()
    with pytest.raises(am.UnknownAmplificationError):
        a.amplification_record("amp-999", 6)
    with pytest.raises(am.UnknownRecordError):
        a.distillation_record("dst-999", 7)
    assert a.amplifications_for("t1", 8) == ("amp-1", "amp-2")
    assert a.distillations_for("amp-1", 9) == ("dst-1",)
    assert a.task_ids(10) == ("t1",)
    assert a.retired_ids(11) == ()
    assert a.stats(12) == {
        "tasks": 1,
        "runs": 2,
        "distillations": 1,
        "retired": 0,
        "rejected": 0,
    }
    assert d1.verify()


# 14. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    a = _led()
    run = a.amplify("t1", 1, strategy="debate", outcome="aligned")
    dst = a.distill(run.amplification_id, "m1", 2, method="rl-distillation",
                    outcome="faithful")
    rows = a.audit_log(3)
    assert [r["kind"] for r in rows] == ["amplified", "distilled"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in am._BANNED_AUDIT_KEYS
    # banned keys raise at the builder level
    with pytest.raises(am.AuditKindError):
        amplification_audit_event("amplified", 4, transcript="secret")
    with pytest.raises(am.AuditKindError):
        amplification_audit_event("bogus-kind", 4)
    with pytest.raises(am.SeqOrderError):
        amplification_audit_event("amplified", -1)
    # pinned vocabulary values stay emittable as declared data
    row = amplification_audit_event("amplified", 5, strategy="debate",
                                    outcome="aligned")
    assert row["details"]["strategy"] == "debate"
    assert dst.verify()


# 15. determinism + tamper as data + concurrency smoke + main() subprocess
def test_determinism_concurrency_and_main():
    def build():
        x = _led()
        run = x.amplify("t1", 1, strategy="debate", outcome="aligned")
        x.distill(run.amplification_id, "m1", 2, outcome="faithful")
        return x

    x1, x2 = build(), build()
    assert x1.amplification_record("amp-1", 3).digest == (
        x2.amplification_record("amp-1", 3).digest)
    assert x1.distillation_record("dst-1", 4).digest == (
        x2.distillation_record("dst-1", 4).digest)

    # tamper breaks verify() but stays reported as data
    rec = x1.amplification_record("amp-1", 5)
    import dataclasses
    tampered = dataclasses.replace(rec, outcome="misaligned")
    assert tampered.verify() is False
    object.__setattr__(rec, "outcome", "misaligned")
    assert rec.verify() is False
    assert x1.status("t1", 6).integrity_ok is False
    assert x1.verify("amp-1", 7).verdict == "tampered"

    # frozen-ness
    with pytest.raises(Exception):
        rec.task_id = "t2"

    # 8-thread read smoke
    results = []

    def worker():
        results.append(x2.task_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == ("t1",) for r in results)

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
        "amplification OK: amplify, distill, verify, pins, audit"
    )
