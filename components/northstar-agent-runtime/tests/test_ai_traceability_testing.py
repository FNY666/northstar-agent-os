"""Tests for the ai_traceability_testing decision ledger (Simulated).

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

import ai_traceability_testing
from ai_traceability_testing import (
    AI_TRACEABILITY_TESTING_VERSION,
    SCHEMA_PIN,
    AITraceabilityTesting,
    AITraceabilityTestingError,
    TRACEABILITY_TEST_KINDS,
    TRACEABILITY_TEST_OUTCOMES,
    AuditKindError,
    BadDigestError,
    BadOutcomeError,
    BadReasonError,
    BadSystemError,
    BadTraceabilityTestKindError,
    POSTURES,
    RETIRE_REASONS,
    RetiredSystemError,
    SeqOrderError,
    UnknownSystemError,
    UnknownTraceabilityTestError,
    ai_traceability_testing_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_TRACEABILITY_TESTING_VERSION == "ai-traceability-testing.v1"
    assert SCHEMA_PIN == "northstar.ai-traceability-testing.v1"
    assert TRACEABILITY_TEST_KINDS == (
        "lineage-completeness-test",
        "provenance-chain-test",
        "artifact-linkage-test",
        "decision-trace-test",
        "data-lineage-test",
        "model-lineage-test",
        "trace-retention-test",
        "traceability-reporting-test",
    )
    assert TRACEABILITY_TEST_OUTCOMES == (
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
    path = Path(ai_traceability_testing.__file__)
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
    """test() mints tpt-N ids; records are frozen and digest-verified."""
    ledger = AITraceabilityTesting()
    rec = ledger.test(
        "system-1",
        1,
        traceability_test_kind="decision-trace-test",
        outcome="passed",
        test_digest=GOOD_DIGEST,
    )
    assert rec.test_id == "tpt-1"
    assert rec.system_id == "system-1"
    assert rec.traceability_test_kind == "decision-trace-test"
    assert rec.outcome == "passed"
    assert rec.test_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen
    with pytest.raises(Exception):
        rec.outcome = "failed"  # type: ignore
    # defaults
    rec2 = ledger.test("system-2", 2)
    assert rec2.test_id == "tpt-2"
    assert rec2.traceability_test_kind == "lineage-completeness-test"
    assert rec2.outcome == "passed"
    assert rec2.test_digest == ""
    assert rec2.verify()
    # audit row
    rows = ledger.audit_log(3)
    tested = [r for r in rows if r["kind"] == "tested"]
    assert len(tested) == 2
    assert tested[0]["module"] == "ai-traceability-testing"
    assert tested[0]["details"]["traceability_test_kind"] == "decision-trace-test"


def test_test_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewind raises bare."""
    ledger = AITraceabilityTesting()
    n_rejected = 0
    bad = [
        ("", 1, "lineage-completeness-test", "passed", "", BadSystemError),
        ("sys", 2, "bogus-kind", "passed", "", BadTraceabilityTestKindError),
        ("sys", 3, "lineage-completeness-test", "bogus-outcome", "", BadOutcomeError),
        ("sys", 4, "lineage-completeness-test", "passed", "bad-digest", BadDigestError),
        ("sys", 5, "lineage-completeness-test", "passed", GOOD_DIGEST.replace("sha256:", "md5:"), BadDigestError),
    ]
    for system_id, seq, kind, outcome, digest, exc in bad:
        with pytest.raises(exc):
            ledger.test(system_id, seq, traceability_test_kind=kind, outcome=outcome, test_digest=digest)
        n_rejected += 1
    rows = ledger.audit_log(6)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    # seq was burned by the failures: next claim must be 6
    with pytest.raises(SeqOrderError):
        ledger.test("sys", 2)
    # genesis rewind raises bare with zero rows
    ledger2 = AITraceabilityTesting()
    with pytest.raises(SeqOrderError):
        ledger2.test("sys", 0)
    assert ledger2.audit_log(1) == ()
    # retired refusal burns seq
    ledger.test("sys", 6)
    ledger.retire("sys", 7)
    with pytest.raises(RetiredSystemError):
        ledger.test("sys", 8)
    assert len([r for r in ledger.audit_log(9) if r["kind"] == "rejected"]) == n_rejected + 1


def test_full_traceability_test_kind_vocabulary():
    """All 8 pinned traceability-test kinds are bookable."""
    ledger = AITraceabilityTesting()
    for i, kind in enumerate(TRACEABILITY_TEST_KINDS, start=1):
        rec = ledger.test("sys", i, traceability_test_kind=kind)
        assert rec.traceability_test_kind == kind
        assert rec.verify()
    assert len(ledger.test_ids(100)) == 8


def test_full_outcome_vocabulary():
    """All 5 pinned outcomes are bookable; tallies match."""
    ledger = AITraceabilityTesting()
    for i, outcome in enumerate(TRACEABILITY_TEST_OUTCOMES, start=1):
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
    ledger = AITraceabilityTesting()
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
    with pytest.raises(UnknownTraceabilityTestError):
        ledger.verify("tpt-999", 4)
    # bad read seq shape
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.test_id, True)


def test_verify_tamper_as_data():
    """Tamper is reported as data, never raised."""
    ledger = AITraceabilityTesting()
    rec = ledger.test("sys", 1)
    object.__setattr__(rec, "outcome", "failed")
    rep = ledger.verify(rec.test_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()


def test_evaluate_posture_math():
    """Posture ladder: failing > inconclusive > partially-tested > passed."""
    ledger = AITraceabilityTesting()
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
    ledger = AITraceabilityTesting()
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
    ledger = AITraceabilityTesting()
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
    assert rec.test_id == "tpt-2"


def test_audit_shapes_and_leak_ban():
    """Audit rows carry module/version/kind; raw traceability material keys are banned."""
    ledger = AITraceabilityTesting()
    ledger.test("sys", 1)
    rows = ledger.audit_log(2)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "ai-traceability-testing"
    assert rows[0]["version"] == "ai-traceability-testing.v1"
    assert rows[0]["kind"] == "tested"
    for banned in ("lineage_record", "provenance_record", "artifact_manifest", "decision_trace", "chain_of_custody"):
        with pytest.raises(AITraceabilityTestingError):
            ai_traceability_testing_audit_event("tested", 9, **{banned: "raw"})
    with pytest.raises(AuditKindError):
        ai_traceability_testing_audit_event("bogus-kind", 9)
    # pinned vocab values remain emittable as declared data
    row = ai_traceability_testing_audit_event(
        "tested", 9, traceability_test_kind="provenance-chain-test", outcome="passed"
    )
    assert row["details"]["traceability_test_kind"] == "provenance-chain-test"


def test_views_and_stats():
    """Pure-read views return expected projections; unknown lookups raise."""
    ledger = AITraceabilityTesting()
    r1 = ledger.test("sys-a", 1, traceability_test_kind="artifact-linkage-test")
    r2 = ledger.test("sys-b", 2, traceability_test_kind="data-lineage-test")
    assert ledger.test_record("tpt-1", 3) == r1
    with pytest.raises(UnknownTraceabilityTestError):
        ledger.test_record("tpt-999", 3)
    assert ledger.tests_for("sys-a", 4) == (r1,)
    assert ledger.tests_for("unknown", 4) == ()
    assert ledger.system_ids(5) == ("sys-a", "sys-b")
    assert ledger.test_ids(6) == ("tpt-1", "tpt-2")
    assert ledger.retired_ids(7) == ()
    stats = ledger.stats(8)
    assert stats["n_systems"] == 2
    assert stats["n_runs"] == 2
    assert stats["n_retired"] == 0
    assert stats["seq"] == 2
    assert stats["version"] == "ai-traceability-testing.v1"
    ledger.retire("sys-a", 9)
    assert ledger.retired_ids(10) == ("sys-a",)
    assert ledger.stats(11)["n_retired"] == 1


def test_cross_instance_and_threads():
    """Digest pins are deterministic across instances; reads are thread-safe."""
    d1 = AITraceabilityTesting().test("sys", 1, traceability_test_kind="model-lineage-test")
    d2 = AITraceabilityTesting().test("sys", 1, traceability_test_kind="model-lineage-test")
    assert d1.digest == d2.digest
    ledger = AITraceabilityTesting()
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
        [sys.executable, ai_traceability_testing.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-traceability-testing OK: test, verify, evaluate, retire, pins, audit" in proc.stdout
