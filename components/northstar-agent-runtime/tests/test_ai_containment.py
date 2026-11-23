"""Tests for the ai_containment decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_containment
from ai_containment import (
    AI_CONTAINMENT_VERSION,
    SCHEMA_PIN,
    CRITICAL_SEVERITY,
    AIContainment,
    AIContainmentError,
    AuditKindError,
    BadDigestError,
    BadMeasureError,
    BadReasonError,
    BadSeverityError,
    BadTargetError,
    MEASURES,
    POSTURES,
    RELEASE_REASONS,
    ReleasedTargetError,
    SeqOrderError,
    UnknownRecordError,
    UnknownTargetError,
    ai_containment_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_CONTAINMENT_VERSION == "ai-containment.v1"
    assert SCHEMA_PIN == "northstar.ai-containment.v1"
    assert CRITICAL_SEVERITY == 75
    assert MEASURES == (
        "network-isolation",
        "tool-revocation",
        "sandbox-quarantine",
        "model-freeze",
        "session-terminate",
        "capability-restrict",
        "checkpoint-rollback",
        "rate-throttle",
    )
    assert POSTURES == ("uncontained", "contained", "breached", "released")
    assert RELEASE_REASONS == ("manual", "superseded", "all-clear", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_containment.__file__)
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
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or node.module.split(".")[0] in allowed


def test_contain_books_record_and_audit():
    """contain() mints cnt-N ids, pins digests, and emits an audit row."""
    ledger = AIContainment()
    rec = ledger.contain(
        "target-1",
        1,
        measure="network-isolation",
        severity=80,
        measure_digest=GOOD_DIGEST,
    )
    assert rec.containment_id == "cnt-1"
    assert rec.target_id == "target-1"
    assert rec.measure == "network-isolation"
    assert rec.severity == 80
    assert rec.measure_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:") and len(rec.digest) == 71
    assert rec.verify()
    # minted ids keep increasing across targets
    rec2 = ledger.contain("target-2", 2, measure="tool-revocation")
    assert rec2.containment_id == "cnt-2"
    rows = ledger.audit_log(3)
    assert len(rows) == 2
    first = rows[0]
    assert first["schema"] == "audit.ndjson/1"
    assert first["module"] == "ai-containment"
    assert first["kind"] == "contained"
    assert first["seq"] == 1
    assert first["details"]["containment_id"] == "cnt-1"
    assert "measure_digest" in first["details"]


def test_contain_rejects_bad_measure_burns_seq():
    """Bad measure fails closed: seq is consumed and a rejected row is booked."""
    ledger = AIContainment()
    with pytest.raises(BadMeasureError):
        ledger.contain("target-1", 1, measure="deploy-nuke")
    rows = ledger.audit_log(2)
    assert len(rows) == 1
    assert rows[0]["kind"] == "rejected"
    assert rows[0]["seq"] == 1
    assert rows[0]["details"]["rejected_kind"] == "BadMeasureError"
    # seq is consumed: seq 1 is now a rewind
    with pytest.raises(SeqOrderError):
        ledger.contain("target-1", 1, measure="network-isolation")
    # next valid seq works
    rec = ledger.contain("target-1", 2)
    assert rec.containment_id == "cnt-1"


def test_contain_rejects_bad_severity_and_bad_digest():
    """Bad severity / bad digest fail closed with their error kinds booked."""
    ledger = AIContainment()
    with pytest.raises(BadSeverityError):
        ledger.contain("target-1", 1, severity=101)
    with pytest.raises(BadSeverityError):
        ledger.contain("target-1", 2, severity=True)
    with pytest.raises(BadDigestError):
        ledger.contain("target-1", 3, measure_digest="not-a-pin")
    rows = ledger.audit_log(4)
    kinds = [r["details"]["rejected_kind"] for r in rows]
    assert kinds == ["BadSeverityError", "BadSeverityError", "BadDigestError"]
    assert ledger.stats(5)["n_records"] == 0


def test_seq_rewind_raises_bare_without_burn():
    """Seq rewinds raise SeqOrderError bare - no seq consumed, no audit row."""
    ledger = AIContainment()
    ledger.contain("target-1", 5)
    with pytest.raises(SeqOrderError):
        ledger.contain("target-1", 5)
    with pytest.raises(SeqOrderError):
        ledger.contain("target-1", 3)
    assert len(ledger.audit_log(6)) == 1
    assert ledger.stats(7)["seq"] == 5


def test_verify_verified_for_intact_record():
    """verify() is a pure read: no seq consumed, no audit row, verdict verified."""
    ledger = AIContainment()
    rec = ledger.contain("target-1", 1)
    rep = ledger.verify(rec.containment_id, 99)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    assert ledger.stats(100)["seq"] == 1  # read seq 99 never consumed
    assert ledger.audit_log(101) == ledger.audit_log(101)[:1]


def test_verify_tampered_after_digest_mutation():
    """Simulated tampering (digest swap in the store) yields verdict tampered."""
    ledger = AIContainment()
    rec = ledger.contain("target-1", 1)
    tampered = dataclasses.replace(rec, digest="sha256:" + "ff" * 32)
    ledger._records[rec.containment_id] = tampered  # simulate store tampering
    rep = ledger.verify(rec.containment_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()  # the report itself is still honestly pinned


def test_verify_unknown_record_raises():
    """verify() on an unknown record id raises fail-closed."""
    ledger = AIContainment()
    with pytest.raises(UnknownRecordError):
        ledger.verify("cnt-999", 1)
    with pytest.raises(UnknownRecordError):
        ledger.verify("", 2)


def test_release_terminal_blocks_new_contain():
    """release() is terminal: later contain() on the target fails closed."""
    ledger = AIContainment()
    ledger.contain("target-1", 1, measure="model-freeze")
    rel = ledger.release("target-1", 2, reason="all-clear")
    assert rel.target_id == "target-1"
    assert rel.reason == "all-clear"
    assert rel.verify()
    rows = ledger.audit_log(3)
    assert rows[-1]["kind"] == "released"
    with pytest.raises(ReleasedTargetError):
        ledger.contain("target-1", 3, measure="rate-throttle")
    with pytest.raises(ReleasedTargetError):
        ledger.release("target-1", 4)
    rows = ledger.audit_log(5)
    assert [r["kind"] for r in rows] == ["contained", "released", "rejected", "rejected"]


def test_release_unknown_target_and_bad_reason():
    """release() on an unknown target or with a bad reason fails closed."""
    ledger = AIContainment()
    with pytest.raises(UnknownTargetError):
        ledger.release("ghost", 1)
    ledger.contain("target-1", 2)
    with pytest.raises(BadReasonError):
        ledger.release("target-1", 3, reason="expired")
    rows = ledger.audit_log(4)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert [r["details"]["rejected_kind"] for r in rejected] == [
        "UnknownTargetError",
        "BadReasonError",
    ]


def test_evaluate_posture_ladder():
    """evaluate() derives released > breached > contained > uncontained as data."""
    ledger = AIContainment()
    # never-seen target: uncontained, zero counts, honest pins
    ev0 = ledger.evaluate("ghost", 1)
    assert ev0.posture == "uncontained"
    assert ev0.n_measures == 0 and ev0.n_critical == 0
    assert ev0.integrity_ok is True
    assert ev0.verify()
    # one critical measure: contained
    rec = ledger.contain("target-1", 2, measure="sandbox-quarantine", severity=90)
    ev1 = ledger.evaluate("target-1", 3)
    assert ev1.posture == "contained"
    assert ev1.n_measures == 1 and ev1.n_critical == 1
    assert ev1.integrity_ok is True
    # tampered digest: breached
    ledger._records[rec.containment_id] = dataclasses.replace(
        rec, digest="sha256:" + "00" * 32
    )
    ev2 = ledger.evaluate("target-1", 4)
    assert ev2.posture == "breached"
    assert ev2.integrity_ok is False
    # release overrides even breached: released
    ledger.release("target-1", 5)
    ev3 = ledger.evaluate("target-1", 6)
    assert ev3.posture == "released"
    assert ev3.n_measures == 1


def test_audit_boundary_rejects_raw_keys():
    """Raw banned keys may not cross the audit boundary; digest pins may."""
    with pytest.raises(AIContainmentError):
        ai_containment_audit_event("contained", 1, sandbox_config={"x": 1})
    row = ai_containment_audit_event(
        "contained", 1, measure_digest=GOOD_DIGEST, measure="network-isolation"
    )
    assert row["details"]["measure_digest"] == GOOD_DIGEST
    with pytest.raises(AuditKindError):
        ai_containment_audit_event("bogus", 2)


def test_views_and_stats():
    """View methods are pure reads with seq shape validation."""
    ledger = AIContainment()
    r1 = ledger.contain("target-1", 1, measure="network-isolation")
    r2 = ledger.contain("target-1", 2, measure="tool-revocation")
    assert ledger.containment_record("cnt-1", 3) == r1
    assert ledger.records_for("target-1", 4) == (r1, r2)
    assert ledger.records_for("ghost", 5) == ()
    assert ledger.target_ids(6) == ("target-1",)
    assert ledger.containment_ids(7) == ("cnt-1", "cnt-2")
    assert ledger.released_ids(8) == ()
    stats = ledger.stats(9)
    assert stats["n_targets"] == 1 and stats["n_records"] == 2
    assert stats["n_released"] == 0 and stats["version"] == AI_CONTAINMENT_VERSION
    with pytest.raises(UnknownRecordError):
        ledger.containment_record("cnt-999", 10)
    with pytest.raises(UnknownTargetError):
        ledger.release_record("ghost", 11)
    with pytest.raises(SeqOrderError):
        ledger.stats("9")


def test_module_main_selfcheck():
    """python -m ai_containment (via file) runs the built-in self-check."""
    path = Path(ai_containment.__file__)
    proc = subprocess.run(
        [sys.executable, str(path)],
        capture_output=True,
        text=True,
        cwd=str(path.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-containment OK" in proc.stdout


def test_thread_safety_smoke():
    """Concurrent contain() calls keep seqs and minted ids consistent."""
    ledger = AIContainment()
    errors: list = []

    def worker(offset: int):
        try:
            for i in range(5):
                ledger.contain(f"target-{offset}-{i}", offset * 100 + i + 1)
        except Exception as exc:  # pragma: no cover - should not happen
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ledger.stats(10_000)["n_records"] == 20
    assert len(set(ledger.containment_ids(10_001))) == 20
