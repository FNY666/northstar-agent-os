"""Tests for the ai_contestability_monitoring decision ledger (Simulated).

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

import ai_contestability_monitoring
from ai_contestability_monitoring import (
    AI_CONTESTABILITY_MONITORING_VERSION,
    SCHEMA_PIN,
    CONTESTABILITY_SIGNALS,
    WATCH_CADENCES,
    CONCERN_KINDS,
    ALERT_LEVELS,
    ALERT_STATUSES,
    VERIFY_VERDICTS,
    POSTURES,
    RETIRE_REASONS,
    EMIT_KINDS,
    AIContestabilityMonitoring,
    AIContestabilityMonitoringError,
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
    ai_contestability_monitoring_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_CONTESTABILITY_MONITORING_VERSION == "ai-contestability-monitoring.v1"
    assert SCHEMA_PIN == "northstar.ai-contestability-monitoring.v1"
    assert CONTESTABILITY_SIGNALS == (
        "contestation-window-rate",
        "appeal-upheld-rate",
        "decision-explanation-coverage-rate",
        "contest-response-latency-rate",
        "contestation-volume-rate",
        "overturn-rate",
        "reconsideration-request-rate",
        "adverse-decision-review-rate",
        "contestant-access-rate",
        "remedy-completion-rate",
    )
    assert WATCH_CADENCES == ("realtime", "minute", "hourly", "daily")
    assert CONCERN_KINDS == (
        "denied-contestation",
        "opaque-decision",
        "missing-explanation",
        "stale-contestation",
        "unanswered-appeal",
        "no-recourse-path",
        "retaliation-risk",
        "contestant-fatigue",
    )
    assert ALERT_LEVELS == ("info", "warning", "critical")
    assert ALERT_STATUSES == ("firing", "acknowledged", "resolved")
    assert VERIFY_VERDICTS == ("verified", "tampered")
    assert POSTURES == (
        "unmonitored",
        "contestability-critical-firing",
        "contestability-firing",
        "contestability-warned",
        "contestability-covered",
        "contestability-quiet",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert EMIT_KINDS == ("monitored", "alerted", "retired", "rejected")
    # contestability vocabulary must not overlap sibling domain signal sets
    assert "disclosure-coverage-rate" not in CONTESTABILITY_SIGNALS
    assert "oversight-coverage-rate" not in CONTESTABILITY_SIGNALS
    assert "harm-output-rate" not in CONTESTABILITY_SIGNALS
    assert "policy-coverage-rate" not in CONTESTABILITY_SIGNALS


def test_stdlib_only_ast():
    """The module imports stdlib names only (AST-verified)."""
    assert stdlib_only() is True


def test_monitor_roundtrip_verify_and_frozen():
    """monitor() roundtrip, minted ctw-N, digest pin, frozen record."""
    led = AIContestabilityMonitoring()
    rec = led.monitor(
        "target-1", 1,
        contestability_signal="contestation-window-rate",
        threshold=0.9, cadence="minute", config_digest=GOOD_DIGEST,
    )
    assert rec.watch_id == "ctw-1"
    assert rec.target_id == "target-1"
    assert rec.contestability_signal == "contestation-window-rate"
    assert rec.threshold == 0.9
    assert rec.cadence == "minute"
    assert rec.config_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.threshold = 0.1  # type: ignore[misc]
    fetched = led.watch_record("ctw-1", 2)
    assert fetched == rec
    assert led.stats(2)["seq"] == 1


def test_bad_inputs_burn_seq_and_book_rejected():
    """Bad inputs: seq burned, rejected audit rows, rewind raises bare."""
    led = AIContestabilityMonitoring()
    bad = [
        ("target", 1, {"contestability_signal": "not-a-signal"}, BadSignalError),
        ("target", 2, {"cadence": "weekly"}, BadCadenceError),
        ("target", 3, {"threshold": True}, BadThresholdError),
        ("target", 4, {"threshold": "high"}, BadThresholdError),
        ("", 5, {}, BadTargetError),
        (123, 6, {}, BadTargetError),  # type: ignore[arg-type]
        ("target", 7, {"config_digest": "nope"}, BadDigestError),
    ]
    rows_before = len(led.audit_log(0))
    for target, seq, kw, exc in bad:
        with pytest.raises(exc):
            led.monitor(target, seq, **kw)  # type: ignore[arg-type]
        assert led.stats(0)["seq"] == seq  # seq consumed (burned)
    rows_after = len(led.audit_log(0))
    rejected = [r for r in led.audit_log(0) if r["kind"] == "rejected"]
    assert rows_after - rows_before == len(bad)
    assert len(rejected) == len(bad)
    # rewind raises bare, consumes nothing, books no row
    with pytest.raises(SeqOrderError):
        led.monitor("target", 3)
    assert len(led.audit_log(0)) == rows_after
    assert led.stats(0)["seq"] == 7


def test_full_signal_vocabulary():
    """All 10 contestability signals book as data."""
    led = AIContestabilityMonitoring()
    for i, sig in enumerate(CONTESTABILITY_SIGNALS, start=1):
        rec = led.monitor(f"target-{i}", i, contestability_signal=sig)
        assert rec.contestability_signal == sig
        assert rec.verify() is True
    assert len(CONTESTABILITY_SIGNALS) == 10
    assert led.stats(0)["n_watches"] == 10


def test_alert_roundtrip_and_chaining():
    """alert() roundtrip, minted cta-N, multiple alerts chain per target."""
    led = AIContestabilityMonitoring()
    led.monitor("target-1", 1, contestability_signal="appeal-upheld-rate")
    a1 = led.alert("target-1", 2, concern_kind="denied-contestation",
                   level="warning", observed_value=0.4, status="firing")
    assert a1.alert_id == "cta-1"
    assert a1.concern_kind == "denied-contestation"
    assert a1.level == "warning"
    assert a1.observed_value == 0.4
    assert a1.status == "firing"
    assert a1.verify() is True
    a2 = led.alert("target-1", 3, concern_kind="opaque-decision",
                   level="critical", observed_value=0.95, status="firing")
    assert a2.alert_id == "cta-2"
    chained = led.alerts_for("target-1", 4)
    assert tuple(a.alert_id for a in chained) == ("cta-1", "cta-2")
    assert led.alert_record("cta-1", 5) == a1
    # read-only calls do not consume seq
    assert led.stats(6)["seq"] == 3


def test_alert_refusals_burn_seq():
    """alert() on unknown/retired targets and bad levels refuse, burning seq."""
    led = AIContestabilityMonitoring()
    with pytest.raises(UnknownTargetError):
        led.alert("ghost", 1, concern_kind="denied-contestation")
    bad = [
        ("target", 2, {"concern_kind": "bogus"}, BadConcernKindError),
        ("target", 3, {"level": "severe"}, BadLevelError),
        ("target", 4, {"observed_value": True}, BadObservedError),
        ("target", 5, {"status": "snoozed"}, BadStatusError),
        ("", 6, {}, BadTargetError),
        (123, 7, {}, BadTargetError),  # type: ignore[arg-type]
        ("target", 8, {"alert_digest": "nope"}, BadDigestError),
    ]
    rows_before = len(led.audit_log(0))
    for target, seq, kw, exc in bad:
        with pytest.raises(exc):
            led.alert(target, seq, **kw)  # type: ignore[arg-type]
        assert led.stats(0)["seq"] == seq  # seq consumed (burned)
    rows_after = len(led.audit_log(0))
    rejected = [r for r in led.audit_log(0) if r["kind"] == "rejected"]
    assert rows_after - rows_before == len(bad)
    assert len(rejected) == len(bad) + 1  # +1 for the unknown-target refusal
    with pytest.raises(UnknownTargetError):
        led.alert("ghost", 9, concern_kind="denied-contestation", level="info")
    rejected = [r for r in led.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == len(bad) + 2
    led.monitor("target", 10)
    led.retire("target", 11)
    with pytest.raises(RetiredTargetError):
        led.alert("target", 12, concern_kind="denied-contestation")
    assert led.stats(0)["seq"] == 12


def test_full_concern_levels_statuses():
    """All 8 concern kinds, 3 levels, 3 statuses book as data."""
    led = AIContestabilityMonitoring()
    led.monitor("target-1", 1)
    seq = 2
    for kind in CONCERN_KINDS:
        for level in ALERT_LEVELS:
            for status in ALERT_STATUSES:
                rec = led.alert("target-1", seq, concern_kind=kind,
                                level=level, status=status)
                assert rec.concern_kind == kind
                assert rec.level == level
                assert rec.status == status
                seq += 1
    assert len(CONCERN_KINDS) == 8
    assert led.stats(0)["n_alerts"] == 8 * 3 * 3


def test_verify_semantics_tamper_as_data_and_read_purity():
    """verify() is pure; tampering reports tampered as data."""
    led = AIContestabilityMonitoring()
    rec = led.monitor("target-1", 1)
    alr = led.alert("target-1", 2, concern_kind="denied-contestation")
    rows_before = len(led.audit_log(0))
    rep = led.verify("ctw-1", 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # same-seq-twice: no audit rows, seq untouched
    rep2 = led.verify("ctw-1", 3)
    assert rep2 == rep
    assert len(led.audit_log(0)) == rows_before
    assert led.stats(0)["seq"] == 2
    # tamper is data, never raised
    object.__setattr__(alr, "concern_kind", "retaliation-risk")
    tampered = led.verify("cta-1", 4)
    assert tampered.verdict == "tampered"
    assert tampered.integrity_ok is False
    assert len(led.audit_log(0)) == rows_before
    with pytest.raises(UnknownRecordError):
        led.verify("ctw-999", 5)
    with pytest.raises(SeqOrderError):
        led.verify("ctw-1", True)
    # both watch and alert ids verify via the same path
    assert led.verify(rec.watch_id, 6).verdict == "verified"


def test_evaluate_posture_ladder_and_precedence():
    """All 5 reachable postures plus critical-outranks precedence."""
    led = AIContestabilityMonitoring()
    led.monitor("t-quiet", 1)
    ev = led.evaluate("t-quiet", 2)
    assert ev.posture == "contestability-quiet"
    assert ev.n_watches == 1 and ev.n_alerts == 0
    assert ev.verify() is True

    led.monitor("t-covered", 3)
    led.alert("t-covered", 4, level="warning", status="resolved")
    assert led.evaluate("t-covered", 5).posture == "contestability-covered"

    led.monitor("t-warned", 6)
    led.alert("t-warned", 7, level="info", status="acknowledged")
    assert led.evaluate("t-warned", 8).posture == "contestability-warned"

    led.monitor("t-firing", 9)
    led.alert("t-firing", 10, level="warning", status="firing")
    evf = led.evaluate("t-firing", 11)
    assert evf.posture == "contestability-firing"
    assert evf.n_firing == 1 and evf.n_critical == 0

    led.monitor("t-critical", 12)
    led.alert("t-critical", 13, level="critical", status="firing")
    evc = led.evaluate("t-critical", 14)
    assert evc.posture == "contestability-critical-firing"
    assert evc.n_critical == 1

    # precedence: critical outranks warning, acknowledged is warned
    led.monitor("t-mix", 15)
    led.alert("t-mix", 16, level="critical", status="acknowledged")
    led.alert("t-mix", 17, level="warning", status="firing")
    assert led.evaluate("t-mix", 18).posture == "contestability-firing"
    with pytest.raises(UnknownTargetError):
        led.evaluate("ghost", 19)


def test_evaluate_read_purity_and_integrity_flip():
    """evaluate() is a pure read; tampered pins flip integrity_ok as data."""
    led = AIContestabilityMonitoring()
    led.monitor("target-1", 1, threshold=0.5)
    led.alert("target-1", 2, concern_kind="stale-contestation",
              level="warning", observed_value=0.7)
    rows_before = len(led.audit_log(0))
    ev = led.evaluate("target-1", 9)
    assert ev.integrity_ok is True
    assert ev.verify() is True
    # read purity: no audit rows, seq untouched
    assert len(led.audit_log(0)) == rows_before
    assert led.stats(0)["seq"] == 2
    # tamper flips integrity_ok as data
    rec = led.watch_record("ctw-1", 0)
    object.__setattr__(rec, "threshold", 0.999)
    ev2 = led.evaluate("target-1", 10)
    assert ev2.integrity_ok is False
    assert ev2.verify() is True
    with pytest.raises(BadTargetError):
        led.evaluate("", 11)


def test_retire_terminality_and_reasons():
    """retire() is terminal; ids never recycled; all 4 reasons book."""
    led = AIContestabilityMonitoring()
    with pytest.raises(UnknownTargetError):
        led.retire("ghost", 1)
    seq = 2
    targets = {}
    for reason in RETIRE_REASONS:
        tid = f"target-{seq}"
        led.monitor(tid, seq)
        seq += 1
        ret = led.retire(tid, seq, reason=reason)
        seq += 1
        assert ret.target_id == tid
        assert ret.reason == reason
        assert ret.verify() is True
        assert tid in led.retired_ids(seq)
        targets[tid] = reason
    first = next(iter(targets))
    # double-retire refused, seq burned
    with pytest.raises(RetiredTargetError):
        led.retire(first, seq)
    seq += 1
    # post-retire mutations refused, reads still work
    with pytest.raises(RetiredTargetError):
        led.monitor(first, seq)
    seq += 1
    with pytest.raises(RetiredTargetError):
        led.alert(first, seq, concern_kind="denied-contestation")
    seq += 1
    second = list(targets)[1]
    with pytest.raises(BadReasonError):
        led.retire(second, seq, reason="bogus")
    assert led.stats(0)["seq"] == seq
    assert led.watches_for(first, 0)
    ev = led.evaluate(first, 0)
    assert ev.posture == "contestability-quiet"
    assert len(RETIRE_REASONS) == 4


def test_seq_discipline_malformed_and_gaps():
    """Malformed seqs raise bare; rewinds bare; gaps allowed."""
    led = AIContestabilityMonitoring()
    for bad in (True, "1", 1.5, None):
        with pytest.raises(SeqOrderError):
            led.monitor("t", bad)  # type: ignore[arg-type]
    led.monitor("t", 10)
    with pytest.raises(SeqOrderError):
        led.monitor("t2", 10)  # rewind raises bare
    assert led.stats(0)["seq"] == 10
    assert len(led.audit_log(0)) == 1  # only the successful monitor
    with pytest.raises(SeqOrderError):
        led.retire("t", -1)
    # gap seqs are fine for mutations
    led.alert("t", 100, concern_kind="no-recourse-path")
    assert led.stats(0)["seq"] == 100


def test_audit_shapes_and_leak_ban():
    """Audit rows carry schema/module/version; raw keys are banned."""
    led = AIContestabilityMonitoring()
    led.monitor("target-1", 1, contestability_signal="remedy-completion-rate",
                threshold=0.8, cadence="hourly", config_digest=GOOD_DIGEST)
    led.alert("target-1", 2, concern_kind="unanswered-appeal",
              level="info", observed_value=0.2, status="acknowledged")
    led.retire("target-1", 3)
    kinds = [r["kind"] for r in led.audit_log(4)]
    assert kinds == ["monitored", "alerted", "retired"]
    row = led.audit_log(4)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-contestability-monitoring"
    assert row["version"] == "ai-contestability-monitoring.v1"
    assert row["details"]["contestability_signal"] == "remedy-completion-rate"
    assert row["details"]["threshold"] == 0.8
    assert row["details"]["config_digest"] == GOOD_DIGEST
    # raw contestability material is banned from the audit boundary
    for key in ("contest_request", "appeal_record", "complainant_identity",
                "contestant_identity", "contested_decision", "decision_rationale",
                "explanation_text", "hearing_transcript", "adjudicator_identity",
                "remedy_plan"):
        with pytest.raises(AIContestabilityMonitoringError):
            ai_contestability_monitoring_audit_event(
                "monitored", 9, **{key: "raw-value"})
    # pinned vocabulary values remain emittable as declared data
    ok = ai_contestability_monitoring_audit_event(
        "alerted", 9, concern_kind="denied-contestation", level="info")
    assert ok["details"]["concern_kind"] == "denied-contestation"
    assert ok["details"]["level"] == "info"
    with pytest.raises(AuditKindError):
        ai_contestability_monitoring_audit_event("bogus-kind", 10)
    with pytest.raises(SeqOrderError):
        ai_contestability_monitoring_audit_event("monitored", True)


def test_views_stats_determinism_and_thread_smoke():
    """Views/stats, cross-instance digest determinism, 8-thread read smoke, main()."""
    def build():
        led = AIContestabilityMonitoring()
        led.monitor("target-1", 1,
                    contestability_signal="contest-response-latency-rate",
                    threshold=0.75, cadence="daily")
        led.alert("target-1", 2, concern_kind="contestant-fatigue",
                  level="warning", observed_value=0.5, status="firing")
        return led

    l1, l2 = build(), build()
    assert l1.watch_record("ctw-1", 0).digest == l2.watch_record("ctw-1", 0).digest
    assert l1.evaluate("target-1", 0).digest == l2.evaluate("target-1", 0).digest
    assert l1.alert_ids(0) == ("cta-1",)
    assert l1.watch_ids(0) == ("ctw-1",)
    assert l1.target_ids(0) == ("target-1",)
    stats = l1.stats(0)
    assert stats["n_targets"] == 1
    assert stats["n_watches"] == 1
    assert stats["n_alerts"] == 1
    assert stats["n_retired"] == 0
    assert stats["version"] == "ai-contestability-monitoring.v1"
    with pytest.raises(UnknownRecordError):
        l1.watch_record("ctw-999", 0)
    with pytest.raises(UnknownRecordError):
        l1.alert_record("cta-999", 0)

    led = build()
    errors = []

    def reader():
        try:
            for _ in range(50):
                led.evaluate("target-1", 9)
                led.verify("ctw-1", 9)
                led.verify("cta-1", 9)
                led.target_ids(9)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    proc = subprocess.run(
        [sys.executable, "-m", "ai_contestability_monitoring"],
        cwd=str(Path(__file__).resolve().parent.parent),
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-contestability-monitoring OK" in proc.stdout
