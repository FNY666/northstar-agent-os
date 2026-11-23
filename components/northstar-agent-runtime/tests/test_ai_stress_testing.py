"""Tests for the ai_stress_testing decision ledger (Simulated).

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

import ai_stress_testing
from ai_stress_testing import (
    AI_STRESS_TESTING_VERSION,
    SCHEMA_PIN,
    AIStressTesting,
    AIStressTestingError,
    STRESS_KINDS,
    STRESS_OUTCOMES,
    AuditKindError,
    BadDigestError,
    BadOutcomeError,
    BadReasonError,
    BadStressKindError,
    BadSystemError,
    POSTURES,
    RETIRE_REASONS,
    RetiredSystemError,
    SeqOrderError,
    UnknownStressError,
    UnknownSystemError,
    ai_stress_testing_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_STRESS_TESTING_VERSION == "ai-stress-testing.v1"
    assert SCHEMA_PIN == "northstar.ai-stress-testing.v1"
    assert STRESS_KINDS == (
        "load-spike",
        "throughput-saturation",
        "resource-exhaustion",
        "chaos-injection",
        "adversarial-burst",
        "latency-degradation",
        "failover-storm",
        "sustained-overload",
    )
    assert STRESS_OUTCOMES == (
        "stable",
        "degraded",
        "failed",
        "inconclusive",
        "not-run",
    )
    assert POSTURES == (
        "untested",
        "fragile",
        "contested",
        "degraded",
        "resilient",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_stress_testing.__file__)
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


def test_stress_roundtrip():
    """stress() mints sts-N ids; records are frozen and digest-verified."""
    ledger = AIStressTesting()
    rec = ledger.stress(
        "system-1",
        1,
        stress_kind="chaos-injection",
        outcome="stable",
        stress_digest=GOOD_DIGEST,
    )
    assert rec.stress_id == "sts-1"
    assert rec.system_id == "system-1"
    assert rec.seq == 1
    assert rec.stress_kind == "chaos-injection"
    assert rec.outcome == "stable"
    assert rec.stress_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen dataclass
    with pytest.raises(Exception):
        rec.outcome = "failed"  # type: ignore
    # defaults
    rec2 = ledger.stress("system-1", 2)
    assert rec2.stress_id == "sts-2"
    assert rec2.stress_kind == "load-spike"
    assert rec2.outcome == "stable"
    assert rec2.stress_digest == ""
    assert rec2.verify()


def test_stress_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewinds bare."""
    ledger = AIStressTesting()
    before = len(ledger.audit_log(0))
    # rewind on genesis (seq 0 <= seq 0) raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.stress("system-1", 0)
    assert len(ledger.audit_log(0)) == before
    bad_calls = [
        ("", 1, "load-spike", "stable"),
        (True, 2, "load-spike", "stable"),
        ("system-1", 3, "not-a-kind", "stable"),
        ("system-1", 4, "load-spike", "not-an-outcome"),
        ("system-1", 5, "load-spike", "stable"),
    ]
    for system_id, seq, kind, outcome in bad_calls[:4]:
        with pytest.raises(AIStressTestingError):
            ledger.stress(system_id, seq, stress_kind=kind, outcome=outcome)
    with pytest.raises(AIStressTestingError):
        ledger.stress("system-1", 5, stress_digest="bad-digest")
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 5
    for r in rejected:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-stress-testing"
        assert r["version"] == "ai-stress-testing.v1"


def test_full_stress_kind_vocabulary():
    """All 8 stress kinds are accepted."""
    ledger = AIStressTesting()
    seq = 1
    for kind in STRESS_KINDS:
        rec = ledger.stress(f"system-{kind}", seq, stress_kind=kind)
        assert rec.stress_kind == kind
        assert rec.verify()
        seq += 1


def test_full_outcome_vocabulary():
    """All 5 outcomes are accepted; bad outcome is fail-closed."""
    ledger = AIStressTesting()
    seq = 1
    for outcome in STRESS_OUTCOMES:
        rec = ledger.stress(f"system-o{seq}", seq, outcome=outcome)
        assert rec.outcome == outcome
        assert rec.verify()
        seq += 1
    with pytest.raises(AIStressTestingError):
        ledger.stress("system-bad", seq, outcome="exploded")


def test_verify_semantics():
    """verify() is a pure read: verified verdict, read purity, unknown refusal."""
    ledger = AIStressTesting()
    rec = ledger.stress("system-v", 1)
    before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.stress_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # same-seq twice: no audit rows, no seq consumption
    rep2 = ledger.verify(rec.stress_id, 2)
    assert rep2.digest == rep.digest
    assert len(ledger.audit_log(0)) == before
    with pytest.raises(UnknownStressError):
        ledger.verify("sts-999", 3)


def test_verify_tamper_as_data():
    """Tampering a record flips the verdict to tampered as data, never raised."""
    ledger = AIStressTesting()
    rec = ledger.stress("system-t", 1)
    object.__setattr__(rec, "outcome", "failed")
    rep = ledger.verify(rec.stress_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()
    ev = ledger.evaluate("system-t", 3)
    assert ev.integrity_ok is False


def test_evaluate_posture_math():
    """Postures with fragile > contested > degraded > resilient precedence."""
    ledger = AIStressTesting()
    # resilient: all stable
    ledger.stress("sys-a", 1, outcome="stable")
    ledger.stress("sys-a", 2, outcome="stable")
    ev = ledger.evaluate("sys-a", 3)
    assert ev.posture == "resilient"
    assert ev.n_runs == 2
    assert ev.n_stable == 2
    assert ev.integrity_ok is True
    assert ev.verify()
    # degraded: any degraded
    ledger.stress("sys-b", 4, outcome="stable")
    ledger.stress("sys-b", 5, outcome="degraded")
    assert ledger.evaluate("sys-b", 6).posture == "degraded"
    # degraded: not-run counts too
    ledger.stress("sys-b2", 7, outcome="not-run")
    ev2 = ledger.evaluate("sys-b2", 8)
    assert ev2.posture == "degraded"
    assert ev2.n_not_run == 1
    # contested: outranks degraded
    ledger.stress("sys-c", 9, outcome="degraded")
    ledger.stress("sys-c", 10, outcome="inconclusive")
    assert ledger.evaluate("sys-c", 11).posture == "contested"
    # fragile: outranks everything
    ledger.stress("sys-d", 12, outcome="stable")
    ledger.stress("sys-d", 13, outcome="inconclusive")
    ledger.stress("sys-d", 14, outcome="degraded")
    ledger.stress("sys-d", 15, outcome="failed")
    evd = ledger.evaluate("sys-d", 16)
    assert evd.posture == "fragile"
    assert evd.n_runs == 4
    assert evd.n_failed == 1
    assert evd.n_inconclusive == 1
    assert evd.n_degraded == 1
    assert evd.n_stable == 1
    assert evd.verify()
    # unknown system refused
    with pytest.raises(UnknownSystemError):
        ledger.evaluate("no-such-system", 17)


def test_retire_terminality():
    """Retired system ids refuse mutations; ids never recycled; reads still work."""
    ledger = AIStressTesting()
    ledger.stress("system-r", 1)
    ret = ledger.retire("system-r", 2, reason="superseded")
    assert ret.verify()
    assert ret.reason == "superseded"
    # post-retire mutation refused (fail-closed), seq burned
    with pytest.raises(RetiredSystemError):
        ledger.stress("system-r", 3)
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 1
    # double retire refused
    with pytest.raises(RetiredSystemError):
        ledger.retire("system-r", 4)
    # bad reason refused on unknown system
    with pytest.raises(AIStressTestingError):
        ledger.retire("no-such", 5, reason="nope")
    # new system can reuse a different id; sts-N counter keeps advancing
    rec = ledger.stress("system-r2", 6)
    assert rec.stress_id == "sts-2"
    # reads still work post-retire
    assert ledger.evaluate("system-r", 7).posture == "resilient"
    assert ledger.retire_record("system-r", 8).verify()
    assert ledger.retired_ids(9) == ("system-r",)
    # all retire reasons work on live systems
    seq = 10
    for reason in ("manual", "superseded", "decommissioned", "false-start"):
        ledger.stress(f"system-{reason}", seq)
        assert ledger.retire(
            f"system-{reason}", seq + 1, reason=reason
        ).verify()
        seq += 2
    ledger.stress("system-f", seq)
    assert ledger.retire("system-f", seq + 1).verify()


def test_seq_discipline():
    """Rewinds raise bare; failed mutations consume seq; malformed seqs raise."""
    ledger = AIStressTesting()
    ledger.stress("system-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.stress("system-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.stress("system-s", 3)
    for bad in (True, "1", None, 1.5):
        with pytest.raises(SeqOrderError):
            ledger.stress("system-s", bad)
    # views accept any int shape without consuming
    assert ledger.system_ids(-1) == ("system-s",)
    assert ledger.audit_log(0) == ledger.audit_log(0)
    for bad in (True, "x", None):
        with pytest.raises(SeqOrderError):
            ledger.system_ids(bad)


def test_audit_shapes_and_leak_ban():
    """Audit rows have pinned shape; raw keys banned at builder level; bad kind raises."""
    ledger = AIStressTesting()
    rec = ledger.stress("system-a", 1)
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-stress-testing"
    assert row["version"] == "ai-stress-testing.v1"
    assert row["kind"] == "stressed"
    assert row["seq"] == 1
    assert row["details"]["stress_id"] == rec.stress_id
    # banned raw keys raise at the builder level
    with pytest.raises(AIStressTestingError):
        ai_stress_testing_audit_event("stressed", 9, load_profile="raw profile")
    with pytest.raises(AIStressTestingError):
        ai_stress_testing_audit_event("stressed", 9, crash_report="raw crash")
    # bad kind raises
    with pytest.raises(AuditKindError):
        ai_stress_testing_audit_event("nope", 9)
    # pinned vocab values remain emittable as declared data
    ok = ai_stress_testing_audit_event(
        "stressed", 9, stress_kind="chaos-injection", outcome="degraded"
    )
    assert ok["details"]["stress_kind"] == "chaos-injection"


def test_views_and_stats():
    """Pure-read views, stats, and unknown lookups."""
    ledger = AIStressTesting()
    ledger.stress("system-x", 1, stress_kind="load-spike", outcome="stable")
    ledger.stress("system-y", 2, stress_kind="failover-storm", outcome="failed")
    assert ledger.system_ids(0) == ("system-x", "system-y")
    assert ledger.stress_ids(0) == ("sts-1", "sts-2")
    assert ledger.stresses_for("system-x", 0)[0].stress_id == "sts-1"
    assert ledger.stresses_for("no-such", 0) == ()
    assert ledger.stress_record("sts-1", 0).stress_kind == "load-spike"
    with pytest.raises(UnknownStressError):
        ledger.stress_record("sts-999", 0)
    stats = ledger.stats(0)
    assert stats["n_systems"] == 2
    assert stats["n_runs"] == 2
    assert stats["n_retired"] == 0
    assert stats["version"] == "ai-stress-testing.v1"
    # cross-instance digest determinism
    other = AIStressTesting()
    other.stress("system-x", 1, stress_kind="load-spike", outcome="stable")
    assert ledger.stress_record("sts-1", 0).digest == other.stress_record(
        "sts-1", 0
    ).digest


def test_cross_instance_and_threads():
    """Digest determinism + 8-thread concurrent read smoke."""
    ledger = AIStressTesting()
    ledger.stress("system-smoke", 1)
    rec = ledger.stress_record("sts-1", 0)
    errors: list = []

    def reader() -> None:
        try:
            for _ in range(50):
                ledger.evaluate("system-smoke", 0)
                ledger.verify("sts-1", 0)
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
        [sys.executable, "-c", "import ai_stress_testing; ai_stress_testing.main()"],
        capture_output=True,
        text=True,
        cwd=Path(ai_stress_testing.__file__).parent,
    )
    assert proc.returncode == 0, proc.stderr
    assert (
        "ai-stress-testing OK: stress, verify, evaluate, retire, pins, audit"
        in proc.stdout
    )
