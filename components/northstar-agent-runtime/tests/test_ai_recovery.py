"""Tests for the ai_recovery decision ledger (Simulated).

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

import ai_recovery
from ai_recovery import (
    AI_RECOVERY_VERSION,
    SCHEMA_PIN,
    AIRecovery,
    AIRecoveryError,
    AuditKindError,
    BadDigestError,
    BadIncidentError,
    BadOutcomeError,
    BadReasonError,
    BadRecoveryKindError,
    POSTURES,
    RECOVERY_KINDS,
    RECOVERY_OUTCOMES,
    RETIRE_REASONS,
    RetiredIncidentError,
    SeqOrderError,
    UnknownIncidentError,
    UnknownRecoveryError,
    ai_recovery_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_RECOVERY_VERSION == "ai-recovery.v1"
    assert SCHEMA_PIN == "northstar.ai-recovery.v1"
    assert RECOVERY_KINDS == (
        "capability-restoration",
        "deployment-rollback",
        "access-revocation",
        "checkpoint-restore",
        "data-restoration",
        "model-retraining",
        "configuration-restore",
        "service-restoration",
    )
    assert RECOVERY_OUTCOMES == ("recovered", "partial", "failed", "inconclusive")
    assert POSTURES == (
        "unaddressed",
        "unrecoverable",
        "contested",
        "partially-recovered",
        "recovered",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_recovery.__file__)
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


def test_recover_roundtrip():
    """recover() mints rcv-N ids; records are frozen and digest-verified."""
    ledger = AIRecovery()
    rec = ledger.recover(
        "incident-1",
        1,
        recovery_kind="deployment-rollback",
        outcome="recovered",
        incident_digest=GOOD_DIGEST,
    )
    assert rec.recovery_id == "rcv-1"
    assert rec.incident_id == "incident-1"
    assert rec.seq == 1
    assert rec.recovery_kind == "deployment-rollback"
    assert rec.outcome == "recovered"
    assert rec.incident_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen dataclass
    with pytest.raises(Exception):
        rec.outcome = "failed"  # type: ignore
    rec2 = ledger.recover("incident-1", 2)
    assert rec2.recovery_id == "rcv-2"


def test_recover_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewinds bare."""
    ledger = AIRecovery()
    before = len(ledger.audit_log(0))
    # rewind on genesis (seq 0 <= seq 0) raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.recover("incident-1", 0)
    assert len(ledger.audit_log(0)) == before
    bad_calls = [
        ("", 1, "capability-restoration", "recovered"),
        (True, 2, "capability-restoration", "recovered"),
        ("incident-1", 3, "not-a-kind", "recovered"),
        ("incident-1", 4, "capability-restoration", "not-an-outcome"),
        ("incident-1", 5, "capability-restoration", "recovered"),
    ]
    # last tuple is valid-shaped; patch digest via kwargs below for the bad digest case
    for incident_id, seq, kind, outcome in bad_calls[:4]:
        with pytest.raises(AIRecoveryError):
            ledger.recover(incident_id, seq, recovery_kind=kind, outcome=outcome)
    with pytest.raises(AIRecoveryError):
        ledger.recover("incident-1", 5, incident_digest="bad-digest")
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 5
    for r in rejected:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-recovery"


def test_full_recovery_kind_vocabulary():
    """All 8 recovery kinds are accepted."""
    ledger = AIRecovery()
    seq = 1
    for kind in RECOVERY_KINDS:
        rec = ledger.recover(f"incident-{kind}", seq, recovery_kind=kind)
        assert rec.recovery_kind == kind
        assert rec.verify()
        seq += 1


def test_full_outcome_vocabulary():
    """All 4 recovery outcomes are accepted."""
    ledger = AIRecovery()
    seq = 1
    for outcome in RECOVERY_OUTCOMES:
        rec = ledger.recover("incident-outcomes", seq, outcome=outcome)
        assert rec.outcome == outcome
        assert rec.verify()
        seq += 1


def test_verify_semantics():
    """verify() is a pure read: verified verdict, read purity, unknown refusal."""
    ledger = AIRecovery()
    rec = ledger.recover("incident-v", 1)
    before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.recovery_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # same-seq twice: no audit rows, no seq consumption
    rep2 = ledger.verify(rec.recovery_id, 2)
    assert rep2.digest == rep.digest
    assert len(ledger.audit_log(0)) == before
    with pytest.raises(UnknownRecoveryError):
        ledger.verify("rcv-999", 3)


def test_verify_tamper_as_data():
    """Tampering a record flips the verdict to tampered as data, never raised."""
    ledger = AIRecovery()
    rec = ledger.recover("incident-t", 1)
    object.__setattr__(rec, "outcome", "failed")
    rep = ledger.verify(rec.recovery_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()
    ev = ledger.evaluate("incident-t", 3)
    assert ev.integrity_ok is False


def test_evaluate_posture_math():
    """All 5 postures, with failed > inconclusive > partial > recovered precedence."""
    ledger = AIRecovery()
    # recovered: all recovered
    ledger.recover("inc-a", 1, outcome="recovered")
    ledger.recover("inc-a", 2, outcome="recovered")
    assert ledger.evaluate("inc-a", 3).posture == "recovered"
    # partially-recovered: any partial
    ledger.recover("inc-b", 4, outcome="recovered")
    ledger.recover("inc-b", 5, outcome="partial")
    assert ledger.evaluate("inc-b", 6).posture == "partially-recovered"
    # contested: any inconclusive outranks partial
    ledger.recover("inc-c", 7, outcome="partial")
    ledger.recover("inc-c", 8, outcome="inconclusive")
    assert ledger.evaluate("inc-c", 9).posture == "contested"
    # unrecoverable: any failed outranks everything
    ledger.recover("inc-d", 10, outcome="recovered")
    ledger.recover("inc-d", 11, outcome="inconclusive")
    ledger.recover("inc-d", 12, outcome="failed")
    ev = ledger.evaluate("inc-d", 13)
    assert ev.posture == "unrecoverable"
    assert ev.n_recoveries == 3
    assert ev.n_failed == 1
    assert ev.n_inconclusive == 1
    assert ev.n_recovered == 1
    assert ev.verify()
    # unknown incident refused
    with pytest.raises(UnknownIncidentError):
        ledger.evaluate("no-such-incident", 14)


def test_retire_terminality():
    """Retired incident ids refuse mutations; ids never recycled; reads still work."""
    ledger = AIRecovery()
    ledger.recover("incident-r", 1)
    ret = ledger.retire("incident-r", 2, reason="superseded")
    assert ret.verify()
    assert ret.reason == "superseded"
    # post-retire mutation refused (fail-closed), seq burned
    before = len(ledger.audit_log(0))
    with pytest.raises(RetiredIncidentError):
        ledger.recover("incident-r", 3)
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 1
    # double retire refused
    with pytest.raises(RetiredIncidentError):
        ledger.retire("incident-r", 4)
    # bad reason refused on unknown incident
    with pytest.raises(AIRecoveryError):
        ledger.retire("no-such", 5, reason="nope")
    # new incident can reuse a different id
    rec = ledger.recover("incident-r2", 6)
    assert rec.recovery_id == "rcv-2"
    # reads still work post-retire
    assert ledger.evaluate("incident-r", 7).posture == "recovered"
    assert ledger.retire_record("incident-r", 8).verify()
    assert ledger.retired_ids(9) == ("incident-r",)
    # all retire reasons work on live incidents
    seq = 10
    for reason in ("manual", "superseded", "decommissioned", "false-start"):
        ledger.recover(f"incident-{reason}", seq)
        assert ledger.retire(f"incident-{reason}", seq + 1, reason=reason).verify()
        seq += 2
    ledger.recover("incident-f", seq)
    assert ledger.retire("incident-f", seq + 1).verify()


def test_seq_discipline():
    """Rewinds raise bare; failed mutations consume seq; malformed seqs raise."""
    ledger = AIRecovery()
    ledger.recover("incident-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.recover("incident-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.recover("incident-s", 3)
    for bad in (True, "1", None, 1.5):
        with pytest.raises(SeqOrderError):
            ledger.recover("incident-s", bad)
    # views accept any int shape without consuming
    assert ledger.incident_ids(-1) == ("incident-s",)
    assert ledger.audit_log(0) == ledger.audit_log(0)
    for bad in (True, "x", None):
        with pytest.raises(SeqOrderError):
            ledger.incident_ids(bad)


def test_audit_shapes_and_leak_ban():
    """Audit rows have pinned shape; raw keys banned at builder level; bad kind raises."""
    ledger = AIRecovery()
    rec = ledger.recover("incident-a", 1)
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-recovery"
    assert row["version"] == "ai-recovery.v1"
    assert row["kind"] == "recovered"
    assert row["seq"] == 1
    assert row["details"]["recovery_id"] == rec.recovery_id
    # banned raw keys raise at the builder level
    with pytest.raises(AIRecoveryError):
        ai_recovery_audit_event("recovered", 9, incident_text="raw incident narrative")
    with pytest.raises(AIRecoveryError):
        ai_recovery_audit_event("recovered", 9, checkpoint_data="raw bytes")
    # bad kind raises
    with pytest.raises(AuditKindError):
        ai_recovery_audit_event("nope", 9)
    # pinned vocab values remain emittable as declared data
    ok = ai_recovery_audit_event(
        "recovered", 9, recovery_kind="deployment-rollback", outcome="recovered"
    )
    assert ok["details"]["recovery_kind"] == "deployment-rollback"


def test_views_and_stats():
    """Pure-read views, stats, and unknown lookups."""
    ledger = AIRecovery()
    ledger.recover("incident-x", 1, recovery_kind="access-revocation")
    ledger.recover("incident-y", 2, recovery_kind="data-restoration", outcome="partial")
    assert ledger.incident_ids(0) == ("incident-x", "incident-y")
    assert ledger.recovery_ids(0) == ("rcv-1", "rcv-2")
    assert ledger.recoveries_for("incident-x", 0)[0].recovery_id == "rcv-1"
    assert ledger.recoveries_for("no-such", 0) == ()
    assert ledger.recovery_record("rcv-1", 0).recovery_kind == "access-revocation"
    with pytest.raises(UnknownRecoveryError):
        ledger.recovery_record("rcv-999", 0)
    stats = ledger.stats(0)
    assert stats["n_incidents"] == 2
    assert stats["n_recoveries"] == 2
    assert stats["n_retired"] == 0
    assert stats["version"] == "ai-recovery.v1"
    # cross-instance digest determinism
    other = AIRecovery()
    other.recover("incident-x", 1, recovery_kind="access-revocation")
    assert ledger.recovery_record("rcv-1", 0).digest == other.recovery_record(
        "rcv-1", 0
    ).digest


def test_cross_instance_and_threads():
    """Digest determinism + 8-thread concurrent read smoke."""
    ledger = AIRecovery()
    ledger.recover("incident-smoke", 1)
    rec = ledger.recovery_record("rcv-1", 0)
    errors: list = []

    def reader() -> None:
        try:
            for _ in range(50):
                ledger.evaluate("incident-smoke", 0)
                ledger.verify("rcv-1", 0)
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
        [sys.executable, "-c", "import ai_recovery; ai_recovery.main()"],
        capture_output=True,
        text=True,
        cwd=Path(ai_recovery.__file__).parent,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-recovery OK: recover, verify, evaluate, retire, pins, audit" in proc.stdout
