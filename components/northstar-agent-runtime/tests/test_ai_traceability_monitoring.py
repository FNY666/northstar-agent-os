"""Tests for the ai_traceability_monitoring decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_traceability_monitoring
from ai_traceability_monitoring import (
    AI_TRACEABILITY_MONITORING_VERSION,
    SCHEMA_PIN,
    TRACEABILITY_SIGNALS,
    WATCH_CADENCES,
    CONCERN_KINDS,
    ALERT_LEVELS,
    ALERT_STATUSES,
    VERIFY_VERDICTS,
    POSTURES,
    RETIRE_REASONS,
    EMIT_KINDS,
    AITraceabilityMonitoring,
    AITraceabilityMonitoringError,
    AuditKindError,
    BadCadenceError,
    BadConcernKindError,
    BadDigestError,
    BadLevelError,
    BadObservedError,
    BadReasonError,
    BadSignalError,
    BadStatusError,
    BadTargetError,
    BadThresholdError,
    RetiredTargetError,
    SeqOrderError,
    UnknownRecordError,
    UnknownTargetError,
    ai_traceability_monitoring_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_TRACEABILITY_MONITORING_VERSION == "ai-traceability-monitoring.v1"
    assert SCHEMA_PIN == "northstar.ai-traceability-monitoring.v1"
    assert TRACEABILITY_SIGNALS == (
        "lineage-coverage-rate",
        "artifact-attribution-rate",
        "decision-trail-completeness-rate",
        "provenance-capture-rate",
        "log-retention-rate",
        "identity-binding-rate",
        "reproducibility-rate",
        "audit-chain-integrity-rate",
        "version-pinning-rate",
        "output-attribution-rate",
    )
    assert WATCH_CADENCES == ("realtime", "minute", "hourly", "daily")
    assert CONCERN_KINDS == (
        "missing-lineage",
        "broken-chain",
        "unattributed-artifact",
        "identity-spoof-gap",
        "retention-lapse",
        "unreproducible-run",
        "fork-without-trail",
        "orphaned-output",
    )
    assert ALERT_LEVELS == ("info", "warning", "critical")
    assert ALERT_STATUSES == ("firing", "acknowledged", "resolved")
    assert VERIFY_VERDICTS == ("verified", "tampered")
    assert POSTURES == (
        "unmonitored",
        "traceability-critical-firing",
        "traceability-firing",
        "traceability-warned",
        "traceability-covered",
        "traceability-quiet",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert EMIT_KINDS == ("monitored", "alerted", "retired", "rejected")
    # traceability vocabulary must not overlap sibling monitoring signal sets
    assert "policy-coverage-rate" not in TRACEABILITY_SIGNALS
    assert "oversight-coverage-rate" not in TRACEABILITY_SIGNALS
    assert "answerability-coverage-rate" not in TRACEABILITY_SIGNALS
    assert "harm-output-rate" not in TRACEABILITY_SIGNALS
    assert "bias-rate" not in TRACEABILITY_SIGNALS
    assert "disclosure-coverage-rate" not in TRACEABILITY_SIGNALS


def test_stdlib_only_ast():
    """The module imports stdlib names only (AST-verified)."""
    assert stdlib_only() is True


def test_monitor_roundtrip_verify_and_frozen():
    """monitor() roundtrip, minted tct-N, digest pin, frozen record."""
    led = AITraceabilityMonitoring()
    rec = led.monitor(
        "sys-1", 1, traceability_signal="lineage-coverage-rate",
        threshold=0.95, cadence="hourly", config_digest=GOOD_DIGEST,
    )
    assert rec.watch_id == "tct-1"
    assert rec.target_id == "sys-1"
    assert rec.traceability_signal == "lineage-coverage-rate"
    assert rec.threshold == 0.95
    assert rec.cadence == "hourly"
    assert rec.config_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:") and len(rec.digest) == 71
    assert rec.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.threshold = 0.1  # type: ignore
    # default values
    rec2 = led.monitor("sys-1", 2)
    assert rec2.watch_id == "tct-2"
    assert rec2.traceability_signal == "lineage-coverage-rate"
    assert rec2.threshold == 0.0
    assert rec2.cadence == "minute"
    assert rec2.config_digest == ""
    assert rec2.verify() is True
    # target registered, posture quiet
    ev = led.evaluate("sys-1", 3)
    assert ev.posture == "traceability-quiet"
    assert ev.n_watches == 2 and ev.n_alerts == 0


def test_bad_inputs_burn_seq_and_book_rejected():
    """Bad monitor inputs consume seq and book a rejected row; rewinds raise bare."""
    led = AITraceabilityMonitoring()
    seq = 1

    def expect_burn(fn, exc):
        nonlocal seq
        with pytest.raises(exc):
            fn(seq)
        seq += 1

    expect_burn(lambda s: led.monitor("", s), BadTargetError)
    expect_burn(lambda s: led.monitor("sys-1", s, traceability_signal="nope"),
                BadSignalError)
    expect_burn(lambda s: led.monitor("sys-1", s, threshold=True),
                BadThresholdError)
    expect_burn(lambda s: led.monitor("sys-1", s, cadence="yearly"),
                BadCadenceError)
    expect_burn(lambda s: led.monitor("sys-1", s, config_digest="bogus"),
                BadDigestError)
    rows = led.audit_log(seq)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 5
    assert all(r["module"] == "ai-traceability-monitoring" for r in rejected)
    # seq was burned: next good call needs the next seq
    rec = led.monitor("sys-1", seq)
    assert rec.watch_id == "tct-1"
    seq += 1
    # rewind raises bare (SeqOrderError), no extra row
    n1 = len(led.audit_log(seq))
    with pytest.raises(SeqOrderError):
        led.monitor("sys-1", 1)
    assert len(led.audit_log(seq)) == n1
    # retired target refused
    led.retire("sys-1", seq)
    seq += 1
    with pytest.raises(RetiredTargetError):
        led.monitor("sys-1", seq)
    assert len(led.audit_log(seq + 1)) == n1 + 2  # retired row + rejected row


def test_full_signal_vocabulary():
    """Every pinned signal books and verifies."""
    led = AITraceabilityMonitoring()
    seq = 1
    for i, sig in enumerate(TRACEABILITY_SIGNALS):
        rec = led.monitor("sys-1", seq, traceability_signal=sig)
        assert rec.traceability_signal == sig
        assert rec.watch_id == f"tct-{i + 1}"
        assert rec.verify() is True
        seq += 1


def test_alert_roundtrip_and_chaining():
    """alert() roundtrip, minted trl-N, chainable, digest pin."""
    led = AITraceabilityMonitoring()
    led.monitor("sys-1", 1)
    a1 = led.alert(
        "sys-1", 2, concern_kind="missing-lineage", level="critical",
        observed_value=0.12, status="firing", alert_digest=GOOD_DIGEST,
    )
    assert a1.alert_id == "trl-1"
    assert a1.concern_kind == "missing-lineage"
    assert a1.level == "critical"
    assert a1.observed_value == 0.12
    assert a1.status == "firing"
    assert a1.verify() is True
    a2 = led.alert("sys-1", 3, concern_kind="broken-chain", level="warning")
    assert a2.alert_id == "trl-2"
    assert a2.verify() is True
    ev = led.evaluate("sys-1", 4)
    assert ev.n_alerts == 2 and ev.n_firing == 2 and ev.n_critical == 1
    assert ev.posture == "traceability-critical-firing"


def test_alert_refusals_burn_seq():
    """Alert refusals (unknown target, bad kind/level/status/digest, retired) burn seq."""
    led = AITraceabilityMonitoring()
    with pytest.raises(UnknownTargetError):
        led.alert("ghost", 1)
    led.monitor("sys-1", 2)
    with pytest.raises(BadConcernKindError):
        led.alert("sys-1", 3, concern_kind="nope")
    with pytest.raises(BadLevelError):
        led.alert("sys-1", 4, level="extreme")
    with pytest.raises(BadStatusError):
        led.alert("sys-1", 5, status="sleeping")
    with pytest.raises(BadDigestError):
        led.alert("sys-1", 6, alert_digest="nope")
    with pytest.raises(BadObservedError):
        led.alert("sys-1", 7, observed_value=True)
    rows = led.audit_log(8)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 6
    # exact rejected-row shape
    assert rejected[0]["details"]["rejected_kind"] == "UnknownTargetError"
    led.retire("sys-1", 8)
    with pytest.raises(RetiredTargetError):
        led.alert("sys-1", 9)


def test_full_concern_levels_statuses():
    """Full 8-concern x 3-level x 3-status vocabulary books."""
    led = AITraceabilityMonitoring()
    led.monitor("sys-1", 1)
    seq = 2
    n = 0
    for kind in CONCERN_KINDS:
        for level in ALERT_LEVELS:
            for status in ALERT_STATUSES:
                a = led.alert("sys-1", seq, concern_kind=kind, level=level,
                              status=status)
                assert a.verify() is True
                n += 1
                seq += 1
    assert n == 8 * 3 * 3 == 72
    ids = led.alert_ids(seq)
    assert len(ids) == n and f"trl-{n}" in ids


def test_verify_semantics_tamper_as_data_and_read_purity():
    """verify() is a pure read: tamper reported as data, same-seq-twice ok, no rows."""
    led = AITraceabilityMonitoring()
    rec = led.monitor("sys-1", 1)
    alr = led.alert("sys-1", 2)
    n0 = len(led.audit_log(3))
    r1 = led.verify(rec.watch_id, 3)
    assert r1.verdict == "verified" and r1.integrity_ok is True
    assert r1.digest.startswith("sha256:")
    r2 = led.verify(rec.watch_id, 3)  # same seq twice: pure read
    assert r2.verdict == "verified"
    assert len(led.audit_log(3)) == n0  # no audit rows
    # tamper reported as data, never raised
    tampered = dataclasses.replace(rec, threshold=999.0)
    led2 = AITraceabilityMonitoring()
    led2._watches["tct-1"] = tampered  # simulate stored tamper
    led2._target_watches["sys-1"] = ["tct-1"]
    rep = led2.verify("tct-1", 4)
    assert rep.verdict == "tampered" and rep.integrity_ok is False
    # unknown record refused
    with pytest.raises(UnknownRecordError):
        led.verify("tct-999", 5)
    with pytest.raises(UnknownRecordError):
        led.verify("trl-999", 5)


def test_evaluate_posture_ladder_and_precedence():
    """Posture ladder: all reachable postures + critical-outranks precedence."""
    led = AITraceabilityMonitoring()
    led.monitor("a", 1)
    assert led.evaluate("a", 2).posture == "traceability-quiet"
    led.monitor("b", 3)
    led.alert("b", 4, concern_kind="missing-lineage", level="warning", status="resolved")
    assert led.evaluate("b", 5).posture == "traceability-covered"
    led.monitor("c", 6)
    led.alert("c", 7, concern_kind="broken-chain", level="info", status="acknowledged")
    assert led.evaluate("c", 8).posture == "traceability-warned"
    led.monitor("d", 9)
    led.alert("d", 10, concern_kind="orphaned-output", level="warning", status="firing")
    assert led.evaluate("d", 11).posture == "traceability-firing"
    led.monitor("e", 12)
    led.alert("e", 13, concern_kind="missing-lineage", level="warning", status="firing")
    led.alert("e", 14, concern_kind="identity-spoof-gap", level="critical", status="firing")
    ev = led.evaluate("e", 15)
    assert ev.posture == "traceability-critical-firing"  # critical outranks
    assert ev.n_critical == 1 and ev.n_firing == 2
    # unknown target refused
    with pytest.raises(UnknownTargetError):
        led.evaluate("ghost", 16)


def test_evaluate_read_purity_and_integrity_flip():
    """evaluate() is pure read; tamper flips integrity_ok."""
    led = AITraceabilityMonitoring()
    led.monitor("sys-1", 1)
    led.alert("sys-1", 2)
    n0 = len(led.audit_log(3))
    ev1 = led.evaluate("sys-1", 3)
    assert ev1.integrity_ok is True
    ev2 = led.evaluate("sys-1", 3)  # same seq twice
    assert ev2.posture == ev1.posture
    assert len(led.audit_log(3)) == n0
    assert ev1.digest == ev2.digest  # deterministic
    # tamper one record -> integrity flips
    w = led.watch_record("tct-1", 4)
    led._watches["tct-1"] = dataclasses.replace(w, threshold=-1.0)
    ev3 = led.evaluate("sys-1", 5)
    assert ev3.integrity_ok is False


def test_retire_terminality_and_reasons():
    """retire() is terminal; ids never recycled; all reasons work; post-retire reads ok."""
    led = AITraceabilityMonitoring()
    led.monitor("sys-1", 1)
    led.alert("sys-1", 2)
    ret = led.retire("sys-1", 3, reason="decommissioned")
    assert ret.reason == "decommissioned"
    assert ret.verify() is True
    with pytest.raises(RetiredTargetError):
        led.retire("sys-1", 4)  # double retire refused
    with pytest.raises(RetiredTargetError):
        led.monitor("sys-1", 5)
    with pytest.raises(RetiredTargetError):
        led.alert("sys-1", 6)
    with pytest.raises(BadReasonError):
        led.retire("sys-1", 7, reason="nope")
    with pytest.raises(UnknownTargetError):
        led.retire("ghost", 8)
    # reads still work after retire
    assert led.watch_record("tct-1", 9).watch_id == "tct-1"
    assert led.alert_record("trl-1", 9).alert_id == "trl-1"
    ev = led.evaluate("sys-1", 10)
    assert ev.posture == "traceability-firing"
    # all four reasons
    led2 = AITraceabilityMonitoring()
    for i, reason in enumerate(("manual", "superseded", "decommissioned", "false-start")):
        tid = f"t{i}"
        led2.monitor(tid, i * 2 + 1)
        r = led2.retire(tid, i * 2 + 2, reason=reason)
        assert r.reason == reason
    assert led2.retired_ids(99) == ("t0", "t1", "t2", "t3")


def test_seq_discipline_malformed_and_gaps():
    """Malformed seqs raise bare; gap seqs allowed; failed mutations burn."""
    led = AITraceabilityMonitoring()
    for bad in (0, -1, True, "1", 1.5, None):
        with pytest.raises(SeqOrderError):
            led.monitor("sys-1", bad)
    assert len(led.audit_log(1)) == 0  # malformed seq: no row burned
    led.monitor("sys-1", 10)  # gap seqs allowed (genesis at 10)
    led.monitor("sys-1", 100)
    assert led.watch_ids(101) == ("tct-1", "tct-2")
    with pytest.raises(SeqOrderError):  # rewind bare
        led.monitor("sys-1", 50)
    # failed mutation consumes its seq
    with pytest.raises(BadSignalError):
        led.monitor("sys-1", 101, traceability_signal="nope")
    rec = led.monitor("sys-1", 102)
    assert rec.watch_id == "tct-3"


def test_audit_shapes_and_leak_ban():
    """Audit rows have the ndjson/1 shape; banned keys raise; bad kind raises."""
    led = AITraceabilityMonitoring()
    led.monitor("sys-1", 1, traceability_signal="provenance-capture-rate")
    led.alert("sys-1", 2, concern_kind="retention-lapse")
    led.retire("sys-1", 3)
    rows = led.audit_log(4)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["monitored", "alerted", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-traceability-monitoring"
        assert r["version"] == "ai-traceability-monitoring.v1"
    # pinned vocab values remain emittable
    assert rows[0]["details"]["traceability_signal"] == "provenance-capture-rate"
    assert rows[0]["details"]["threshold"] == 0.0
    # banned raw-material keys raise
    for banned in ("lineage_graph", "provenance_record", "decision_trail",
                   "audit_chain", "replay_log", "identity_token", "sbom"):
        with pytest.raises(AITraceabilityMonitoringError):
            ai_traceability_monitoring_audit_event("monitored", 9, **{banned: "x"})
    # traceability-specific keys banned too
    with pytest.raises(AITraceabilityMonitoringError):
        ai_traceability_monitoring_audit_event("alerted", 9, chain_of_custody="x")
    # bad kind
    with pytest.raises(AuditKindError):
        ai_traceability_monitoring_audit_event("nope", 9)
    with pytest.raises(AuditKindError):
        ai_traceability_monitoring_audit_event("", 9)


def test_views_stats_determinism_and_thread_smoke():
    """Views/stats, unknown lookups, cross-instance digest determinism, 8-thread reads."""
    a = AITraceabilityMonitoring()
    b = AITraceabilityMonitoring()
    for led in (a, b):
        led.monitor("sys-1", 1, traceability_signal="reproducibility-rate",
                    threshold=0.8, cadence="daily")
        led.alert("sys-1", 2, concern_kind="unreproducible-run", level="info",
                  status="acknowledged")
    wa, wb = a.watch_record("tct-1", 3), b.watch_record("tct-1", 3)
    assert wa.digest == wb.digest  # cross-instance determinism
    assert a.alert_record("trl-1", 3).digest == b.alert_record("trl-1", 3).digest
    assert a.watches_for("sys-1", 3) == b.watches_for("sys-1", 3)
    assert a.alerts_for("sys-1", 3) == b.alerts_for("sys-1", 3)
    assert a.target_ids(3) == ("sys-1",)
    assert a.watch_ids(3) == ("tct-1",)
    assert a.alert_ids(3) == ("trl-1",)
    assert a.retired_ids(3) == ()
    st = a.stats(3)
    assert st == {"n_targets": 1, "n_watches": 1, "n_alerts": 1, "n_retired": 0,
                  "seq": 2, "version": "ai-traceability-monitoring.v1"}
    assert len(a.audit_log(3)) == 2
    # unknown lookups
    with pytest.raises(UnknownRecordError):
        a.watch_record("tct-9", 3)
    with pytest.raises(UnknownRecordError):
        a.alert_record("trl-9", 3)
    assert a.watches_for("ghost", 3) == ()
    assert a.alerts_for("ghost", 3) == ()
    # 8-thread read smoke
    errs = []

    def reader():
        try:
            for _ in range(50):
                a.verify("tct-1", 3)
                a.evaluate("sys-1", 3)
                a.stats(3)
        except Exception as exc:  # pragma: no cover
            errs.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    # frozen-ness of all record types
    with pytest.raises(dataclasses.FrozenInstanceError):
        wa.threshold = 0.0  # type: ignore
    # main() subprocess check
    proc = subprocess.run(
        [sys.executable, str(Path(ai_traceability_monitoring.__file__))],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-traceability-monitoring OK" in proc.stdout
