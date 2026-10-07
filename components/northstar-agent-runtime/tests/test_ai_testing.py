"""Tests for the ai_testing decision ledger (Simulated).

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

import ai_testing
from ai_testing import (
    AI_TESTING_VERSION,
    SCHEMA_PIN,
    AITesting,
    AITestingError,
    TEST_KINDS,
    TEST_OUTCOMES,
    AuditKindError,
    BadDigestError,
    BadOutcomeError,
    BadReasonError,
    BadSystemError,
    BadTestKindError,
    POSTURES,
    RETIRE_REASONS,
    RetiredSystemError,
    SeqOrderError,
    UnknownSystemError,
    UnknownTestError,
    ai_testing_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_TESTING_VERSION == "ai-testing.v1"
    assert SCHEMA_PIN == "northstar.ai-testing.v1"
    assert TEST_KINDS == (
        "unit-test",
        "integration-test",
        "adversarial-test",
        "red-team-exercise",
        "eval-suite",
        "benchmark",
        "conformance-test",
        "regression-test",
    )
    assert TEST_OUTCOMES == ("passed", "failed", "partial", "inconclusive", "not-run")
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
    path = Path(ai_testing.__file__)
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
    """test() mints tst-N ids; records are frozen and digest-verified."""
    ledger = AITesting()
    rec = ledger.test(
        "system-1",
        1,
        test_kind="adversarial-test",
        outcome="passed",
        test_digest=GOOD_DIGEST,
    )
    assert rec.test_id == "tst-1"
    assert rec.system_id == "system-1"
    assert rec.seq == 1
    assert rec.test_kind == "adversarial-test"
    assert rec.outcome == "passed"
    assert rec.test_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen dataclass
    with pytest.raises(Exception):
        rec.outcome = "failed"  # type: ignore
    # defaults
    rec2 = ledger.test("system-1", 2)
    assert rec2.test_id == "tst-2"
    assert rec2.test_kind == "unit-test"
    assert rec2.outcome == "passed"
    assert rec2.test_digest == ""
    assert rec2.verify()


def test_test_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewinds bare."""
    ledger = AITesting()
    before = len(ledger.audit_log(0))
    # rewind on genesis (seq 0 <= seq 0) raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.test("system-1", 0)
    assert len(ledger.audit_log(0)) == before
    bad_calls = [
        ("", 1, "unit-test", "passed"),
        (True, 2, "unit-test", "passed"),
        ("system-1", 3, "not-a-kind", "passed"),
        ("system-1", 4, "unit-test", "not-an-outcome"),
        ("system-1", 5, "unit-test", "passed"),
    ]
    for system_id, seq, kind, outcome in bad_calls[:4]:
        with pytest.raises(AITestingError):
            ledger.test(system_id, seq, test_kind=kind, outcome=outcome)
    with pytest.raises(AITestingError):
        ledger.test("system-1", 5, test_digest="bad-digest")
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 5
    for r in rejected:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-testing"
        assert r["version"] == "ai-testing.v1"


def test_full_test_kind_vocabulary():
    """All 8 test kinds are accepted."""
    ledger = AITesting()
    seq = 1
    for kind in TEST_KINDS:
        rec = ledger.test(f"system-{kind}", seq, test_kind=kind)
        assert rec.test_kind == kind
        assert rec.verify()
        seq += 1


def test_full_outcome_vocabulary():
    """All 5 outcomes are accepted; bad outcome is fail-closed."""
    ledger = AITesting()
    seq = 1
    for outcome in TEST_OUTCOMES:
        rec = ledger.test(f"system-o{seq}", seq, outcome=outcome)
        assert rec.outcome == outcome
        assert rec.verify()
        seq += 1
    with pytest.raises(AITestingError):
        ledger.test("system-bad", seq, outcome="exploded")


def test_verify_semantics():
    """verify() is a pure read: verified verdict, read purity, unknown refusal."""
    ledger = AITesting()
    rec = ledger.test("system-v", 1)
    before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.test_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # same-seq twice: no audit rows, no seq consumption
    rep2 = ledger.verify(rec.test_id, 2)
    assert rep2.digest == rep.digest
    assert len(ledger.audit_log(0)) == before
    with pytest.raises(UnknownTestError):
        ledger.verify("tst-999", 3)


def test_verify_tamper_as_data():
    """Tampering a record flips the verdict to tampered as data, never raised."""
    ledger = AITesting()
    rec = ledger.test("system-t", 1)
    object.__setattr__(rec, "outcome", "failed")
    rep = ledger.verify(rec.test_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()
    ev = ledger.evaluate("system-t", 3)
    assert ev.integrity_ok is False


def test_evaluate_posture_math():
    """Postures with failing > inconclusive > partially-tested > passed precedence."""
    ledger = AITesting()
    # passed: all passed
    ledger.test("sys-a", 1, outcome="passed")
    ledger.test("sys-a", 2, outcome="passed")
    ev = ledger.evaluate("sys-a", 3)
    assert ev.posture == "passed"
    assert ev.n_runs == 2
    assert ev.n_passed == 2
    assert ev.integrity_ok is True
    assert ev.verify()
    # partially-tested: any partial
    ledger.test("sys-b", 4, outcome="passed")
    ledger.test("sys-b", 5, outcome="partial")
    assert ledger.evaluate("sys-b", 6).posture == "partially-tested"
    # partially-tested: not-run counts too
    ledger.test("sys-b2", 7, outcome="not-run")
    ev2 = ledger.evaluate("sys-b2", 8)
    assert ev2.posture == "partially-tested"
    assert ev2.n_not_run == 1
    # inconclusive: outranks partial
    ledger.test("sys-c", 9, outcome="partial")
    ledger.test("sys-c", 10, outcome="inconclusive")
    assert ledger.evaluate("sys-c", 11).posture == "inconclusive"
    # failing: outranks everything
    ledger.test("sys-d", 12, outcome="passed")
    ledger.test("sys-d", 13, outcome="inconclusive")
    ledger.test("sys-d", 14, outcome="partial")
    ledger.test("sys-d", 15, outcome="failed")
    evd = ledger.evaluate("sys-d", 16)
    assert evd.posture == "failing"
    assert evd.n_runs == 4
    assert evd.n_failed == 1
    assert evd.n_inconclusive == 1
    assert evd.n_partial == 1
    assert evd.n_passed == 1
    assert evd.verify()
    # unknown system refused
    with pytest.raises(UnknownSystemError):
        ledger.evaluate("no-such-system", 17)


def test_retire_terminality():
    """Retired system ids refuse mutations; ids never recycled; reads still work."""
    ledger = AITesting()
    ledger.test("system-r", 1)
    ret = ledger.retire("system-r", 2, reason="superseded")
    assert ret.verify()
    assert ret.reason == "superseded"
    # post-retire mutation refused (fail-closed), seq burned
    with pytest.raises(RetiredSystemError):
        ledger.test("system-r", 3)
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 1
    # double retire refused
    with pytest.raises(RetiredSystemError):
        ledger.retire("system-r", 4)
    # bad reason refused on unknown system
    with pytest.raises(AITestingError):
        ledger.retire("no-such", 5, reason="nope")
    # new system can reuse a different id; tst-N counter keeps advancing
    rec = ledger.test("system-r2", 6)
    assert rec.test_id == "tst-2"
    # reads still work post-retire
    assert ledger.evaluate("system-r", 7).posture == "passed"
    assert ledger.retire_record("system-r", 8).verify()
    assert ledger.retired_ids(9) == ("system-r",)
    # all retire reasons work on live systems
    seq = 10
    for reason in ("manual", "superseded", "decommissioned", "false-start"):
        ledger.test(f"system-{reason}", seq)
        assert ledger.retire(f"system-{reason}", seq + 1, reason=reason).verify()
        seq += 2
    ledger.test("system-f", seq)
    assert ledger.retire("system-f", seq + 1).verify()


def test_seq_discipline():
    """Rewinds raise bare; failed mutations consume seq; malformed seqs raise."""
    ledger = AITesting()
    ledger.test("system-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.test("system-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.test("system-s", 3)
    for bad in (True, "1", None, 1.5):
        with pytest.raises(SeqOrderError):
            ledger.test("system-s", bad)
    # views accept any int shape without consuming
    assert ledger.system_ids(-1) == ("system-s",)
    assert ledger.audit_log(0) == ledger.audit_log(0)
    for bad in (True, "x", None):
        with pytest.raises(SeqOrderError):
            ledger.system_ids(bad)


def test_audit_shapes_and_leak_ban():
    """Audit rows have pinned shape; raw keys banned at builder level; bad kind raises."""
    ledger = AITesting()
    rec = ledger.test("system-a", 1)
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-testing"
    assert row["version"] == "ai-testing.v1"
    assert row["kind"] == "tested"
    assert row["seq"] == 1
    assert row["details"]["test_id"] == rec.test_id
    # banned raw keys raise at the builder level
    with pytest.raises(AITestingError):
        ai_testing_audit_event("tested", 9, test_data="raw test data")
    with pytest.raises(AITestingError):
        ai_testing_audit_event("tested", 9, answer_key="raw answers")
    # bad kind raises
    with pytest.raises(AuditKindError):
        ai_testing_audit_event("nope", 9)
    # pinned vocab values remain emittable as declared data
    ok = ai_testing_audit_event(
        "tested", 9, test_kind="red-team-exercise", outcome="failed"
    )
    assert ok["details"]["test_kind"] == "red-team-exercise"


def test_views_and_stats():
    """Pure-read views, stats, and unknown lookups."""
    ledger = AITesting()
    ledger.test("system-x", 1, test_kind="benchmark", outcome="passed")
    ledger.test("system-y", 2, test_kind="eval-suite", outcome="failed")
    assert ledger.system_ids(0) == ("system-x", "system-y")
    assert ledger.test_ids(0) == ("tst-1", "tst-2")
    assert ledger.tests_for("system-x", 0)[0].test_id == "tst-1"
    assert ledger.tests_for("no-such", 0) == ()
    assert ledger.test_record("tst-1", 0).test_kind == "benchmark"
    with pytest.raises(UnknownTestError):
        ledger.test_record("tst-999", 0)
    stats = ledger.stats(0)
    assert stats["n_systems"] == 2
    assert stats["n_runs"] == 2
    assert stats["n_retired"] == 0
    assert stats["version"] == "ai-testing.v1"
    # cross-instance digest determinism
    other = AITesting()
    other.test("system-x", 1, test_kind="benchmark", outcome="passed")
    assert ledger.test_record("tst-1", 0).digest == other.test_record(
        "tst-1", 0
    ).digest


def test_cross_instance_and_threads():
    """Digest determinism + 8-thread concurrent read smoke."""
    ledger = AITesting()
    ledger.test("system-smoke", 1)
    rec = ledger.test_record("tst-1", 0)
    errors: list = []

    def reader() -> None:
        try:
            for _ in range(50):
                ledger.evaluate("system-smoke", 0)
                ledger.verify("tst-1", 0)
                ledger.audit_log(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert rec.verify()


def test_main_subprocess():
    """main() self-check runs green in a subprocess."""
    proc = subprocess.run(
        [sys.executable, "-c", "import ai_testing; ai_testing.main()"],
        capture_output=True,
        text=True,
        cwd=Path(ai_testing.__file__).parent,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-testing OK: test, verify, evaluate, retire, pins, audit" in proc.stdout
