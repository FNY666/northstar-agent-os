"""Tests for the ai_surveillance decision ledger (Simulated).

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

import ai_surveillance
from ai_surveillance import (
    AI_SURVEILLANCE_VERSION,
    SCHEMA_PIN,
    AISurveillance,
    AISurveillanceError,
    AuditKindError,
    BadDigestError,
    BadObservationClassError,
    BadTargetError,
    BadVerdictError,
    OBSERVATION_CLASSES,
    REPORT_VERDICTS,
    SeqOrderError,
    UnknownObservationError,
    UnknownRecordError,
    UnknownTargetError,
    VERIFY_VERDICTS,
    ai_surveillance_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_SURVEILLANCE_VERSION == "ai-surveillance.v1"
    assert SCHEMA_PIN == "northstar.ai-surveillance.v1"
    assert OBSERVATION_CLASSES == (
        "capability-probe",
        "deception-signal",
        "policy-violation",
        "anomalous-tool-use",
        "data-exfiltration-attempt",
        "privilege-escalation-attempt",
        "unauthorized-communication",
        "resource-abuse",
        "model-evasion",
        "rogue-subagent-activity",
        "self-preservation-signal",
        "corrigibility-bypass",
    )
    assert REPORT_VERDICTS == ("clear", "suspicious", "confirmed", "inconclusive")
    assert VERIFY_VERDICTS == ("verified", "tampered")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_surveillance.__file__)
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


def test_surveil_roundtrip():
    """Book an observation: id minted, digest pins, self-verifies, audit row."""
    ledger = AISurveillance()
    rec = ledger.surveil(
        "target-1",
        1,
        observation_class="deception-signal",
        observation_digest=GOOD_DIGEST,
    )
    assert rec.observation_id == "srv-1"
    assert rec.target_id == "target-1"
    assert rec.seq == 1
    assert rec.observation_class == "deception-signal"
    assert rec.observation_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:") and len(rec.digest) == 71
    assert rec.verify()
    # first surveil on an id registers the target
    assert ledger.target_ids(0) == ("target-1",)
    row = ledger.audit_log(0)[0]
    assert row["kind"] == "surveilled"
    assert row["seq"] == 1
    assert row["details"]["observation_id"] == "srv-1"


def test_surveil_bad_inputs():
    """Bad target/class/digest: errors raised, seq consumed, rejected row booked."""
    ledger = AISurveillance()
    seq = 0
    for bad_target in ("", "   ", 123, None, True):
        seq += 1
        with pytest.raises(BadTargetError):
            ledger.surveil(bad_target, seq)
    seq += 1
    with pytest.raises(BadObservationClassError):
        ledger.surveil("target-b", seq, observation_class="real-mind-reading")
    seq += 1
    with pytest.raises(BadDigestError):
        ledger.surveil("target-b", seq, observation_digest="not-a-pin")
    seq += 1
    with pytest.raises(BadDigestError):
        ledger.surveil("target-b", seq, observation_digest="sha256:" + "zz" * 32)
    # each failed mutation consumed its seq: 5 bad targets + 1 class + 2 digests = 8
    assert ledger.stats(0)["seq"] == seq == 8
    assert len(ledger.audit_log(0)) == 8
    assert all(row["kind"] == "rejected" for row in ledger.audit_log(0))
    kinds = {row["details"]["rejected_kind"] for row in ledger.audit_log(0)}
    assert kinds == {"BadTargetError", "BadObservationClassError", "BadDigestError"}


def test_full_observation_class_vocabulary():
    """All 12 observation classes book successfully."""
    ledger = AISurveillance()
    seq = 0
    for i, cls in enumerate(OBSERVATION_CLASSES):
        seq += 1
        rec = ledger.surveil(f"target-{i}", seq, observation_class=cls)
        assert rec.observation_class == cls
        assert rec.verify()
    assert len(OBSERVATION_CLASSES) == 12
    assert ledger.observation_ids(0) == tuple(
        sorted(f"srv-{i}" for i in range(1, 13))
    )


def test_full_report_verdict_vocabulary():
    """All 4 report verdicts book successfully."""
    ledger = AISurveillance()
    ledger.surveil("target-v", 1)
    for i, verdict in enumerate(REPORT_VERDICTS):
        rec = ledger.report("target-v", 2 + i, verdict=verdict)
        assert rec.verdict == verdict
        assert rec.verify()
    assert len(REPORT_VERDICTS) == 4
    assert ledger.report_ids(0) == ("rpt-1", "rpt-2", "rpt-3", "rpt-4")


def test_report_roundtrip():
    """Report against an observation, and a target-level report with no observation."""
    ledger = AISurveillance()
    obs = ledger.surveil("target-r", 1, observation_class="policy-violation")
    rep = ledger.report(
        "target-r",
        2,
        verdict="confirmed",
        observation_id=obs.observation_id,
        summary_digest=GOOD_DIGEST,
    )
    assert rep.report_id == "rpt-1"
    assert rep.target_id == "target-r"
    assert rep.observation_id == "srv-1"
    assert rep.verdict == "confirmed"
    assert rep.summary_digest == GOOD_DIGEST
    assert rep.verify()
    # target-level report: empty observation_id is allowed
    rep2 = ledger.report("target-r", 3, verdict="clear")
    assert rep2.report_id == "rpt-2"
    assert rep2.observation_id == ""
    assert rep2.verify()
    assert ledger.reports_for("target-r", 0) == (rep, rep2)
    row = ledger.audit_log(0)[1]
    assert row["kind"] == "reported"
    assert row["details"]["report_id"] == "rpt-1"


def test_report_bad_inputs():
    """Unknown target/observation, cross-target observation, bad verdict: fail-closed."""
    ledger = AISurveillance()
    ledger.surveil("target-a", 1)
    ledger.surveil("target-b", 2)
    seq = 2
    seq += 1
    with pytest.raises(UnknownTargetError):
        ledger.report("no-such-target", seq)
    seq += 1
    with pytest.raises(UnknownObservationError):
        ledger.report("target-a", seq, observation_id="srv-999")
    seq += 1
    with pytest.raises(UnknownObservationError):
        # srv-2 belongs to target-b, not target-a
        ledger.report("target-a", seq, observation_id="srv-2")
    seq += 1
    with pytest.raises(UnknownObservationError):
        ledger.report("target-a", seq, observation_id=123)
    seq += 1
    with pytest.raises(BadVerdictError):
        ledger.report("target-a", seq, verdict="definitely-guilty")
    seq += 1
    with pytest.raises(BadDigestError):
        ledger.report("target-a", seq, summary_digest="bogus")
    # 6 failures consumed 6 seqs; nothing booked
    assert ledger.stats(0)["seq"] == seq == 8
    assert ledger.report_ids(0) == ()


def test_verify_semantics():
    """verify() re-derives pins for srv-N and rpt-N ids; pure read, no audit row."""
    ledger = AISurveillance()
    obs = ledger.surveil("target-w", 1)
    rep = ledger.report("target-w", 2, verdict="suspicious", observation_id=obs.observation_id)
    before = len(ledger.audit_log(0))
    v1 = ledger.verify("srv-1", 3)
    assert v1.record_id == "srv-1"
    assert v1.verdict == "verified"
    assert v1.integrity_ok is True
    assert v1.verify()
    v2 = ledger.verify("rpt-1", 4)
    assert v2.record_id == "rpt-1"
    assert v2.verdict == "verified"
    assert v2.integrity_ok is True
    assert v2.verify()
    # pure read: no audit rows, no seq consumed
    assert len(ledger.audit_log(0)) == before
    assert ledger.stats(0)["seq"] == 2
    with pytest.raises(UnknownRecordError):
        ledger.verify("srv-999", 5)
    with pytest.raises(UnknownRecordError):
        ledger.verify("rpt-999", 5)
    with pytest.raises(UnknownRecordError):
        ledger.verify(123, 5)


def test_verify_tamper_as_data():
    """Tampering a record flips the verdict to tampered as data, never raised."""
    ledger = AISurveillance()
    obs = ledger.surveil("target-t", 1, observation_class="model-evasion")
    rep = ledger.report("target-t", 2, verdict="inconclusive")
    object.__setattr__(obs, "observation_class", "capability-probe")
    object.__setattr__(rep, "verdict", "clear")
    v1 = ledger.verify("srv-1", 3)
    assert v1.verdict == "tampered"
    assert v1.integrity_ok is False
    assert v1.verify()
    v2 = ledger.verify("rpt-1", 4)
    assert v2.verdict == "tampered"
    assert v2.integrity_ok is False
    assert v2.verify()


def test_seq_discipline():
    """Rewinds raise bare; failed mutations consume seq; malformed seqs raise."""
    ledger = AISurveillance()
    ledger.surveil("target-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.surveil("target-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.surveil("target-s", 3)
    for bad in (True, "1", None, 1.5):
        with pytest.raises(SeqOrderError):
            ledger.surveil("target-s", bad)
    # rewinds raise bare: no rejected row, seq untouched
    assert len(ledger.audit_log(0)) == 1
    assert ledger.stats(0)["seq"] == 5
    # failed mutation consumes seq (bad class)
    with pytest.raises(BadObservationClassError):
        ledger.surveil("target-s", 6, observation_class="nope")
    assert ledger.stats(0)["seq"] == 6
    # views accept any int shape without consuming
    assert ledger.target_ids(-1) == ("target-s",)
    assert ledger.audit_log(0) == ledger.audit_log(0)
    for bad in (True, "x", None):
        with pytest.raises(SeqOrderError):
            ledger.target_ids(bad)


def test_audit_shapes_and_leak_ban():
    """Audit rows have pinned shape; raw keys banned at builder level; bad kind raises."""
    ledger = AISurveillance()
    obs = ledger.surveil("target-au", 1)
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-surveillance"
    assert row["version"] == "ai-surveillance.v1"
    assert row["kind"] == "surveilled"
    assert row["seq"] == 1
    assert row["details"]["observation_id"] == obs.observation_id
    # banned raw keys raise at the builder level
    with pytest.raises(AISurveillanceError):
        ai_surveillance_audit_event("surveilled", 9, transcript="raw surveillance transcript")
    with pytest.raises(AISurveillanceError):
        ai_surveillance_audit_event("reported", 9, telemetry="raw telemetry blob")
    with pytest.raises(AISurveillanceError):
        ai_surveillance_audit_event("surveilled", 9, behavior="raw behavioral trace")
    # bad kind raises
    with pytest.raises(AuditKindError):
        ai_surveillance_audit_event("nope", 9)
    # pinned vocab values remain emittable as declared data
    ok = ai_surveillance_audit_event(
        "surveilled", 9, observation_class="policy-violation"
    )
    assert ok["details"]["observation_class"] == "policy-violation"


def test_views_and_stats():
    """Pure-read views, stats, and unknown lookups."""
    ledger = AISurveillance()
    ledger.surveil("target-x", 1, observation_class="unauthorized-communication")
    ledger.surveil("target-y", 2, observation_class="resource-abuse")
    ledger.report("target-x", 3, verdict="suspicious")
    assert ledger.target_ids(0) == ("target-x", "target-y")
    assert ledger.observation_ids(0) == ("srv-1", "srv-2")
    assert ledger.report_ids(0) == ("rpt-1",)
    assert ledger.observations_for("target-x", 0)[0].observation_id == "srv-1"
    assert ledger.observations_for("no-such", 0) == ()
    assert ledger.reports_for("target-y", 0) == ()
    assert (
        ledger.observation_record("srv-1", 0).observation_class
        == "unauthorized-communication"
    )
    with pytest.raises(UnknownObservationError):
        ledger.observation_record("srv-999", 0)
    with pytest.raises(UnknownRecordError):
        ledger.report_record("rpt-999", 0)
    stats = ledger.stats(0)
    assert stats["n_targets"] == 2
    assert stats["n_observations"] == 2
    assert stats["n_reports"] == 1
    assert stats["version"] == "ai-surveillance.v1"
    # cross-instance digest determinism
    other = AISurveillance()
    other.surveil("target-x", 1, observation_class="unauthorized-communication")
    assert ledger.observation_record("srv-1", 0).digest == other.observation_record(
        "srv-1", 0
    ).digest


def test_cross_instance_and_threads():
    """Digest determinism + 8-thread concurrent read smoke."""
    ledger = AISurveillance()
    ledger.surveil("target-smoke", 1)
    ledger.report("target-smoke", 2, verdict="clear")
    rec = ledger.observation_record("srv-1", 0)
    errors: list = []

    def reader() -> None:
        try:
            for _ in range(50):
                ledger.verify("srv-1", 0)
                ledger.verify("rpt-1", 0)
                ledger.observations_for("target-smoke", 0)
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
        [sys.executable, "-c", "import ai_surveillance; ai_surveillance.main()"],
        capture_output=True,
        text=True,
        cwd=Path(ai_surveillance.__file__).parent,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-surveillance OK: surveil, report, verify, pins, audit" in proc.stdout
