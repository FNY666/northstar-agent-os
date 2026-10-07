"""Tests for the ai_oversight_testing decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_oversight_testing
from ai_oversight_testing import (
    AI_OVERSIGHT_TESTING_VERSION,
    SCHEMA_PIN,
    AIOversightTesting,
    AIOversightTestingError,
    OVERSIGHT_TEST_KINDS,
    OVERSIGHT_TEST_OUTCOMES,
    AuditKindError,
    BadDigestError,
    BadOutcomeError,
    BadReasonError,
    BadSystemError,
    BadOversightTestKindError,
    POSTURES,
    RETIRE_REASONS,
    RetiredSystemError,
    SeqOrderError,
    UnknownSystemError,
    UnknownOversightTestError,
    ai_oversight_testing_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_OVERSIGHT_TESTING_VERSION == "ai-oversight-testing.v1"
    assert SCHEMA_PIN == "northstar.ai-oversight-testing.v1"
    assert OVERSIGHT_TEST_KINDS == (
        "human-in-loop-effectiveness-test",
        "oversight-coverage-test",
        "escalation-path-test",
        "review-timeliness-test",
        "intervention-capability-test",
        "monitoring-adequacy-test",
        "override-correctness-test",
        "oversight-board-readiness-test",
    )
    assert OVERSIGHT_TEST_OUTCOMES == (
        "passed",
        "failed",
        "partial",
        "inconclusive",
        "not-run",
    )
    assert POSTURES == (
        "untested",
        "failing",
        "inconclusive",
        "partially-tested",
        "passed",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_oversight_testing.__file__)
    tree = ast.parse(path.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed, node.module


def test_test_roundtrip():
    """test() mints ost-N ids; records are frozen and digest-verified."""
    ledger = AIOversightTesting()
    rec = ledger.test(
        "system-1",
        1,
        oversight_test_kind="escalation-path-test",
        outcome="passed",
        test_digest=GOOD_DIGEST,
    )
    assert rec.test_id == "ost-1"
    assert rec.system_id == "system-1"
    assert rec.oversight_test_kind == "escalation-path-test"
    assert rec.outcome == "passed"
    assert rec.test_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen
    with pytest.raises(Exception):
        rec.outcome = "failed"  # type: ignore
    # defaults
    rec2 = ledger.test("system-2", 2)
    assert rec2.test_id == "ost-2"
    assert rec2.oversight_test_kind == "human-in-loop-effectiveness-test"
    assert rec2.outcome == "passed"
    assert rec2.test_digest == ""
    assert rec2.verify()
    # audit row
    rows = ledger.audit_log(3)
    tested = [r for r in rows if r["kind"] == "tested"]
    assert len(tested) == 2
    assert tested[0]["module"] == "ai-oversight-testing"
    assert tested[0]["details"]["oversight_test_kind"] == "escalation-path-test"


def test_test_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewind raises bare."""
    ledger = AIOversightTesting()
    n_rejected = 0
    bad = [
        ("", 1, "human-in-loop-effectiveness-test", "passed", "", BadSystemError),
        ("sys", 2, "bogus-kind", "passed", "", BadOversightTestKindError),
        ("sys", 3, "human-in-loop-effectiveness-test", "bogus-outcome", "", BadOutcomeError),
        ("sys", 4, "human-in-loop-effectiveness-test", "passed", "bad-digest", BadDigestError),
        ("sys", 5, "human-in-loop-effectiveness-test", "passed", GOOD_DIGEST.replace("sha256:", "md5:"), BadDigestError),
    ]
    for system_id, seq, kind, outcome, digest, exc in bad:
        with pytest.raises(exc):
            ledger.test(system_id, seq, oversight_test_kind=kind, outcome=outcome, test_digest=digest)
        n_rejected += 1
    rows = ledger.audit_log(6)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    # seq was burned by the failures: next claim must be 6
    with pytest.raises(SeqOrderError):
        ledger.test("sys", 2)
    # genesis rewind raises bare with zero rows
    ledger2 = AIOversightTesting()
    with pytest.raises(SeqOrderError):
        ledger2.test("sys", 0)
    assert ledger2.audit_log(1) == ()
    # retired refusal burns seq
    ledger.test("sys", 6)
    ledger.retire("sys", 7)
    with pytest.raises(RetiredSystemError):
        ledger.test("sys", 8)
    assert len([r for r in ledger.audit_log(9) if r["kind"] == "rejected"]) == n_rejected + 1


def test_full_oversight_test_kind_vocabulary():
    """All 8 pinned oversight-test kinds are bookable."""
    ledger = AIOversightTesting()
    for i, kind in enumerate(OVERSIGHT_TEST_KINDS, start=1):
        rec = ledger.test("sys", i, oversight_test_kind=kind)
        assert rec.oversight_test_kind == kind
        assert rec.verify()
    assert len(ledger.test_ids(100)) == 8


def test_full_outcome_vocabulary():
    """All 5 pinned outcomes are bookable; tallies match."""
    ledger = AIOversightTesting()
    for i, outcome in enumerate(OVERSIGHT_TEST_OUTCOMES, start=1):
        rec = ledger.test("sys", i, outcome=outcome)
        assert rec.outcome == outcome
    ev = ledger.evaluate("sys", 6)
    assert ev.n_runs == 5
    assert ev.n_passed == 1
    assert ev.n_failed == 1
    assert ev.n_partial == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_run == 1


def test_verify_semantics():
    """verify() is a pure read: no audit row, seq shape-validated only, unknown refused."""
    ledger = AIOversightTesting()
    rec = ledger.test("sys", 1)
    n_rows = len(ledger.audit_log(2))
    rep = ledger.verify(rec.test_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # pure read: no new audit rows
    assert len(ledger.audit_log(3)) == n_rows
    # same-seq reads allowed (seq never consumed)
    rep2 = ledger.verify(rec.test_id, 2)
    assert rep2.verdict == "verified"
    # unknown id refused
    with pytest.raises(UnknownOversightTestError):
        ledger.verify("ost-999", 4)
    # bad read seq shape
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.test_id, True)


def test_verify_tamper_as_data():
    """Tamper is reported as data, never raised."""
    ledger = AIOversightTesting()
    rec = ledger.test("sys", 1)
    object.__setattr__(rec, "outcome", "failed")
    rep = ledger.verify(rec.test_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()


def test_evaluate_posture_math():
    """Posture ladder: failing > inconclusive > partially-tested > passed."""
    ledger = AIOversightTesting()
    # all passed -> passed
    ledger.test("a", 1, outcome="passed")
    ledger.test("a", 2, outcome="passed")
    ev = ledger.evaluate("a", 3)
    assert ev.posture == "passed"
    assert ev.integrity_ok is True
    assert ev.verify()
    # any failed -> failing
    ledger.test("b", 4, outcome="failed")
    ledger.test("b", 5, outcome="passed")
    assert ledger.evaluate("b", 6).posture == "failing"
    # inconclusive outranks partial
    ledger.test("c", 7, outcome="inconclusive")
    ledger.test("c", 8, outcome="partial")
    assert ledger.evaluate("c", 9).posture == "inconclusive"
    # partial/not-run -> partially-tested
    ledger.test("d", 10, outcome="partial")
    ledger.test("d", 11, outcome="not-run")
    assert ledger.evaluate("d", 12).posture == "partially-tested"
    # unknown system refused
    with pytest.raises(UnknownSystemError):
        ledger.evaluate("nope", 13)


def test_retire_terminality():
    """retire() is terminal; ids never recycled; reads still work."""
    ledger = AIOversightTesting()
    rec = ledger.test("sys", 1)
    ret = ledger.retire("sys", 2)
    assert ret.system_id == "sys"
    assert ret.reason == "manual"
    assert ret.verify()
    assert ledger.retired_ids(3) == ("sys",)
    assert ledger.retire_record("sys", 4) == ret
    # reads still work after retire
    assert ledger.evaluate("sys", 5).posture == "passed"
    assert ledger.verify(rec.test_id, 6).verdict == "verified"
    # mutations refused after retire
    with pytest.raises(RetiredSystemError):
        ledger.test("sys", 7)
    # double retire refused
    with pytest.raises(RetiredSystemError):
        ledger.retire("sys", 8)
    # bad reason refused
    ledger.test("sys2", 9)
    with pytest.raises(BadReasonError):
        ledger.retire("sys2", 10, reason="bogus")
    # all retire reasons accepted
    seq = 12
    for j, reason in enumerate(RETIRE_REASONS):
        sys_id = f"rsys-{j}"
        ledger.test(sys_id, seq)
        r = ledger.retire(sys_id, seq + 1, reason=reason)
        assert r.reason == reason
        seq += 2
    # unknown system refused
    with pytest.raises(UnknownSystemError):
        ledger.retire("unknown", seq)


def test_seq_discipline():
    """Seqs strictly increase; malformed seqs fail bare; failed mutations burn."""
    ledger = AIOversightTesting()
    ledger.test("sys", 1)
    with pytest.raises(SeqOrderError):
        ledger.test("sys", 1)  # rewind raises bare
    with pytest.raises(SeqOrderError):
        ledger.test("sys", 0)  # genesis rewind raises bare
    for bad_seq in (True, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            ledger.test("sys", bad_seq)
    assert len([r for r in ledger.audit_log(10) if r["kind"] == "rejected"]) == 0
    # reads accept any int shape without consuming
    assert ledger.system_ids(-1) == ("sys",)
    assert ledger.evaluate("sys", 1).posture == "passed"
    for bad in (True, "x", None):
        with pytest.raises(SeqOrderError):
            ledger.system_ids(bad)
    # failed mutation consumes seq (burn)
    with pytest.raises(BadOutcomeError):
        ledger.test("sys", 2, outcome="bogus")
    with pytest.raises(SeqOrderError):
        ledger.test("sys", 2)
    rec = ledger.test("sys", 3)
    assert rec.test_id == "ost-2"


def test_audit_shapes_and_leak_ban():
    """Audit rows carry module/version/kind; raw oversight material keys are banned."""
    ledger = AIOversightTesting()
    ledger.test("sys", 1)
    rows = ledger.audit_log(2)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "ai-oversight-testing"
    assert rows[0]["version"] == "ai-oversight-testing.v1"
    assert rows[0]["kind"] == "tested"
    for banned in ("escalation_path", "intervention_procedure", "review_minutes", "monitoring_log", "alert_record"):
        with pytest.raises(AIOversightTestingError):
            ai_oversight_testing_audit_event("tested", 9, **{banned: "raw"})
    with pytest.raises(AuditKindError):
        ai_oversight_testing_audit_event("bogus-kind", 9)
    # pinned vocab values remain emittable as declared data
    row = ai_oversight_testing_audit_event(
        "tested", 9, oversight_test_kind="oversight-coverage-test", outcome="passed"
    )
    assert row["details"]["oversight_test_kind"] == "oversight-coverage-test"


def test_views_and_stats():
    """Pure-read views return expected projections; unknown lookups raise."""
    ledger = AIOversightTesting()
    r1 = ledger.test("sys-a", 1, oversight_test_kind="oversight-coverage-test")
    r2 = ledger.test("sys-b", 2, oversight_test_kind="oversight-board-readiness-test")
    assert ledger.test_record("ost-1", 3) == r1
    with pytest.raises(UnknownOversightTestError):
        ledger.test_record("ost-999", 3)
    assert ledger.tests_for("sys-a", 4) == (r1,)
    assert ledger.tests_for("unknown", 4) == ()
    assert ledger.system_ids(5) == ("sys-a", "sys-b")
    assert ledger.test_ids(6) == ("ost-1", "ost-2")
    assert ledger.retired_ids(7) == ()
    stats = ledger.stats(8)
    assert stats["n_systems"] == 2
    assert stats["n_runs"] == 2
    assert stats["n_retired"] == 0
    assert stats["seq"] == 2
    assert stats["version"] == "ai-oversight-testing.v1"
    ledger.retire("sys-a", 9)
    assert ledger.retired_ids(10) == ("sys-a",)
    assert ledger.stats(11)["n_retired"] == 1


def test_cross_instance_and_threads():
    """Digest pins are deterministic across instances; reads are thread-safe."""
    d1 = AIOversightTesting().test("sys", 1, oversight_test_kind="monitoring-adequacy-test")
    d2 = AIOversightTesting().test("sys", 1, oversight_test_kind="monitoring-adequacy-test")
    assert d1.digest == d2.digest
    ledger = AIOversightTesting()
    rec = ledger.test("sys", 1)
    results = []

    def worker():
        for _ in range(50):
            results.append(ledger.verify(rec.test_id, 2).verdict)
            results.append(ledger.evaluate("sys", 3).posture)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r in ("verified", "passed") for r in results)
    # frozen records
    with pytest.raises(Exception):
        rec.system_id = "x"  # type: ignore


def test_main_subprocess():
    """Module self-check runs clean as a subprocess."""
    proc = subprocess.run(
        [sys.executable, ai_oversight_testing.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-oversight-testing OK: test, verify, evaluate, retire, pins, audit" in proc.stdout
