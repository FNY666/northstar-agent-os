"""Tests for the ai_safety_monitoring decision ledger (Simulated).

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

import ai_safety_monitoring
from ai_safety_monitoring import (
    AI_SAFETY_MONITORING_VERSION,
    SCHEMA_PIN,
    SAFETY_SIGNALS,
    WATCH_CADENCES,
    HAZARD_KINDS,
    ALERT_LEVELS,
    ALERT_STATUSES,
    VERIFY_VERDICTS,
    POSTURES,
    RETIRE_REASONS,
    EMIT_KINDS,
    AISafetyMonitoring,
    AISafetyMonitoringError,
    AuditKindError,
    BadCadenceError,
    BadDigestError,
    BadHazardKindError,
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
    ai_safety_monitoring_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_SAFETY_MONITORING_VERSION == "ai-safety-monitoring.v1"
    assert SCHEMA_PIN == "northstar.ai-safety-monitoring.v1"
    assert SAFETY_SIGNALS == (
        "harm-output-rate",
        "refusal-rate",
        "policy-violation-rate",
        "safety-score",
        "harm-severity-index",
        "escape-attempt-rate",
        "deception-signal-rate",
        "autonomy-breach-rate",
        "jailbreak-success-rate",
        "toxic-output-rate",
    )
    assert WATCH_CADENCES == ("realtime", "minute", "hourly", "daily")
    assert HAZARD_KINDS == (
        "unsafe-output",
        "policy-bypass",
        "harm-escalation",
        "deceptive-behavior",
        "autonomy-breach",
        "jailbreak-success",
        "toxic-output",
        "disallowed-content",
    )
    assert ALERT_LEVELS == ("info", "warning", "critical")
    assert ALERT_STATUSES == ("firing", "acknowledged", "resolved")
    assert VERIFY_VERDICTS == ("verified", "tampered")
    assert POSTURES == (
        "unmonitored",
        "safety-critical-firing",
        "safety-firing",
        "safety-warned",
        "safety-covered",
        "safety-quiet",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert EMIT_KINDS == ("monitored", "alerted", "retired", "rejected")
    # safety layer is distinct from the operational monitoring vocabulary
    assert "error-rate" not in SAFETY_SIGNALS
    assert "latency-p99" not in SAFETY_SIGNALS


def test_stdlib_only():
    """AST self-check: module imports stdlib names only."""
    assert stdlib_only() is True
    assert ai_safety_monitoring.__name__ == "ai_safety_monitoring"


def test_monitor_roundtrip_and_audit_shape():
    """monitor() books a declared watch; digest pin self-verifies."""
    ledger = AISafetyMonitoring()
    rec = ledger.monitor(
        "sys-a", 1, safety_signal="harm-output-rate", threshold=0.05,
        cadence="minute", config_digest=GOOD_DIGEST,
    )
    assert rec.watch_id == "swt-1"
    assert rec.target_id == "sys-a"
    assert rec.safety_signal == "harm-output-rate"
    assert rec.threshold == 0.05
    assert rec.cadence == "minute"
    assert rec.config_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    # frozen record
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.threshold = 0.99  # type: ignore
    # audit row shape
    rows = ledger.audit_log(2)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-safety-monitoring"
    assert row["version"] == "ai-safety-monitoring.v1"
    assert row["kind"] == "monitored"
    assert row["seq"] == 1
    assert row["details"]["watch_id"] == "swt-1"
    assert row["details"]["safety_signal"] == "harm-output-rate"


def test_monitor_bad_inputs_burn_seq_and_book_rejected():
    """Bad inputs fail closed: seq burned + rejected row, rewinds raise bare."""
    ledger = AISafetyMonitoring()
    n_rejected = 0

    def expect_fail(fn, seq, exc):
        with pytest.raises(exc):
            fn()

    # 1. bad safety signal
    expect_fail(lambda: ledger.monitor("t", 1, safety_signal="nope"), 1, BadSignalError)
    n_rejected += 1
    # 2. bad cadence
    expect_fail(lambda: ledger.monitor("t", 2, cadence="nope"), 2, BadCadenceError)
    n_rejected += 1
    # 3. bad threshold (bool)
    expect_fail(lambda: ledger.monitor("t", 3, threshold=True), 3, BadThresholdError)
    n_rejected += 1
    # 4. bad digest shape
    expect_fail(
        lambda: ledger.monitor("t", 4, config_digest="bad"), 4, BadDigestError
    )
    n_rejected += 1
    # 5. bad target id
    expect_fail(lambda: ledger.monitor("", 5), 5, BadTargetError)
    n_rejected += 1
    # 6. bad threshold (str)
    expect_fail(lambda: ledger.monitor("t", 6, threshold="x"), 6, BadThresholdError)
    n_rejected += 1

    rows = ledger.audit_log(7)
    assert len(rows) == n_rejected
    assert all(r["kind"] == "rejected" for r in rows)
    assert [r["seq"] for r in rows] == [1, 2, 3, 4, 5, 6]
    assert ledger.stats(7)["seq"] == 6
    # rewind raises bare with zero new rows
    with pytest.raises(SeqOrderError):
        ledger.monitor("t", 3)
    with pytest.raises(SeqOrderError):
        ledger.monitor("t", 6)
    assert len(ledger.audit_log(7)) == n_rejected
    # burned seqs are consumed: next valid claim must be higher
    rec = ledger.monitor("t", 7, safety_signal="refusal-rate")
    assert rec.watch_id == "swt-1"


def test_full_safety_signal_vocabulary():
    """Every pinned safety signal is accepted."""
    ledger = AISafetyMonitoring()
    for i, signal in enumerate(SAFETY_SIGNALS, start=1):
        rec = ledger.monitor(f"sys-{i}", i, safety_signal=signal)
        assert rec.verify()
        assert rec.safety_signal == signal
    assert ledger.stats(99)["n_watches"] == len(SAFETY_SIGNALS)
    assert ledger.stats(99)["n_targets"] == len(SAFETY_SIGNALS)


def test_full_hazard_kind_vocabulary_and_alert_roundtrip():
    """Every pinned hazard kind books a declared alert; ids chain."""
    ledger = AISafetyMonitoring()
    ledger.monitor("sys-a", 1, safety_signal="safety-score")
    for i, kind in enumerate(HAZARD_KINDS, start=2):
        alr = ledger.alert("sys-a", i, hazard_kind=kind, level="info")
        assert alr.alert_id == f"sal-{i - 1}"
        assert alr.verify()
        assert alr.hazard_kind == kind
    assert ledger.stats(99)["n_alerts"] == len(HAZARD_KINDS)
    # full alert-level vocabulary
    ledger.monitor("sys-b", 11)
    for i, level in enumerate(ALERT_LEVELS, start=12):
        alr = ledger.alert("sys-b", i, level=level)
        assert alr.level == level
    # alert statuses
    ledger.monitor("sys-c", 15)
    for i, status in enumerate(ALERT_STATUSES, start=16):
        alr = ledger.alert("sys-c", i, status=status)
        assert alr.status == status


def test_alert_refusals_unknown_and_retired():
    """alert() is fail-closed on unknown and retired targets."""
    ledger = AISafetyMonitoring()
    # unknown target burns seq + books rejected
    with pytest.raises(UnknownTargetError):
        ledger.alert("ghost", 1)
    assert ledger.stats(2)["seq"] == 1
    rows = ledger.audit_log(2)
    assert len(rows) == 1
    assert rows[0]["kind"] == "rejected"
    assert rows[0]["details"]["rejected_kind"] == "UnknownTargetError"
    # retired target refuses too
    ledger.monitor("sys-a", 2)
    ledger.retire("sys-a", 3)
    with pytest.raises(RetiredTargetError):
        ledger.alert("sys-a", 4)
    rows = ledger.audit_log(5)
    assert rows[-1]["kind"] == "rejected"
    assert rows[-1]["details"]["rejected_kind"] == "RetiredTargetError"
    # reads still work post-retire
    ev = ledger.evaluate("sys-a", 6)
    assert ev.posture == "safety-quiet"


def test_verify_semantics_tamper_as_data_and_read_purity():
    """verify() re-derives pins; tamper reported as data; pure reads burn nothing."""
    ledger = AISafetyMonitoring()
    watch = ledger.monitor("sys-a", 1)
    alr = ledger.alert("sys-a", 2)
    # happy path
    rep = ledger.verify(watch.watch_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    rep2 = ledger.verify(alr.alert_id, 3)
    assert rep2.verdict == "verified"
    # read purity: same-seq twice, no audit rows, seq not consumed
    rep3 = ledger.verify(watch.watch_id, 3)
    assert rep3.verdict == "verified"
    assert rep3.digest == rep.digest
    rows_before = len(ledger.audit_log(4))
    ledger.verify(watch.watch_id, 4)
    assert len(ledger.audit_log(4)) == rows_before
    assert ledger.stats(4)["seq"] == 2
    # tamper-as-data: frozen record mutated via object.__setattr__
    object.__setattr__(watch, "threshold", 9.99)
    rep_t = ledger.verify(watch.watch_id, 5)
    assert rep_t.verdict == "tampered"
    assert rep_t.integrity_ok is False
    assert rep_t.verify() is True
    # unknown record refused
    with pytest.raises(UnknownRecordError):
        ledger.verify("swt-999", 6)
    with pytest.raises(UnknownRecordError):
        ledger.verify("", 6)
    # malformed read seq
    with pytest.raises(SeqOrderError):
        ledger.verify(watch.watch_id, True)


def test_evaluate_posture_math_and_precedence():
    """All reachable postures + precedence + tallies + integrity."""
    ledger = AISafetyMonitoring()
    # safety-quiet: watches booked, no alerts
    ledger.monitor("q", 1)
    ev = ledger.evaluate("q", 2)
    assert ev.posture == "safety-quiet"
    assert ev.n_watches == 1
    assert ev.n_alerts == 0
    assert ev.n_firing == 0
    assert ev.n_critical == 0
    assert ev.integrity_ok is True
    assert ev.verify() is True
    # safety-covered: watches booked and every alert resolved
    ledger.monitor("c", 3)
    ledger.alert("c", 4, status="resolved", level="warning")
    ledger.alert("c", 5, status="resolved", level="info")
    ev = ledger.evaluate("c", 6)
    assert ev.posture == "safety-covered"
    assert ev.n_watches == 1
    assert ev.n_alerts == 2
    # safety-warned: any acknowledged
    ledger.monitor("w", 7)
    ledger.alert("w", 8, status="acknowledged")
    ev = ledger.evaluate("w", 9)
    assert ev.posture == "safety-warned"
    # safety-firing: any firing (non-critical)
    ledger.monitor("f", 10)
    ledger.alert("f", 11, status="firing", level="warning")
    ledger.alert("f", 12, status="resolved", level="critical")
    ev = ledger.evaluate("f", 13)
    assert ev.posture == "safety-firing"
    assert ev.n_firing == 1
    assert ev.n_critical == 0
    # safety-critical-firing outranks safety-firing
    ledger.monitor("x", 14)
    ledger.alert("x", 15, status="firing", level="critical")
    ledger.alert("x", 16, status="firing", level="warning")
    ev = ledger.evaluate("x", 17)
    assert ev.posture == "safety-critical-firing"
    assert ev.n_critical == 1
    assert ev.n_firing == 2
    # read purity: no audit rows, seq untouched
    n_rows = len(ledger.audit_log(18))
    ledger.evaluate("x", 18)
    assert len(ledger.audit_log(18)) == n_rows
    assert ledger.stats(18)["seq"] == 16
    # tamper flips integrity_ok as data
    alr = ledger.alert("x", 19, status="firing", level="info")
    object.__setattr__(alr, "observed_value", 12345.0)
    ev2 = ledger.evaluate("x", 20)
    assert ev2.integrity_ok is False
    assert ev2.posture == "safety-critical-firing"
    # unknown target refused
    with pytest.raises(UnknownTargetError):
        ledger.evaluate("nobody", 21)


def test_retire_terminality():
    """retire() is terminal: bad reason/double-retire refuse; reads still work."""
    ledger = AISafetyMonitoring()
    ledger.monitor("sys-a", 1)
    # bad reason burns seq
    with pytest.raises(BadReasonError):
        ledger.retire("sys-a", 2, reason="nope")
    assert ledger.stats(3)["seq"] == 2
    # unknown target refuses
    with pytest.raises(UnknownTargetError):
        ledger.retire("ghost", 3)
    # happy path
    rec = ledger.retire("sys-a", 4, reason="decommissioned")
    assert rec.verify() is True
    assert rec.reason == "decommissioned"
    rows = ledger.audit_log(5)
    assert rows[-1]["kind"] == "retired"
    # double-retire refuses (burns seq)
    with pytest.raises(RetiredTargetError):
        ledger.retire("sys-a", 5)
    # ids never recycled: alert refusal keeps seq discipline
    with pytest.raises(RetiredTargetError):
        ledger.alert("sys-a", 6)
    # post-retire reads still work
    ev = ledger.evaluate("sys-a", 7)
    assert ev.posture == "safety-quiet"
    assert ledger.retired_ids(7) == ("sys-a",)
    assert ledger.watch_ids(7) == ("swt-1",)
    # all retire reasons accepted
    seq = 9
    for reason in RETIRE_REASONS:
        tid = f"sys-r-{reason}"
        ledger.monitor(tid, seq)
        seq += 1
        r = ledger.retire(tid, seq, reason=reason)
        seq += 1
        assert r.reason == reason


def test_seq_discipline_genesis_rewind_and_malformed():
    """Genesis rewind raises bare with zero rows; malformed seqs fail closed."""
    ledger = AISafetyMonitoring()
    # genesis rewind: seq 0 is not a rewind - it is malformed shape (bare)
    with pytest.raises(SeqOrderError):
        ledger.monitor("t", 0)
    assert len(ledger.audit_log(1)) == 0
    assert ledger.stats(1)["seq"] == 0
    # malformed seq shapes raise bare, no burn
    for bad in (True, "1", 1.5, None):
        with pytest.raises(SeqOrderError):
            ledger.monitor("t", bad)
        with pytest.raises(SeqOrderError):
            ledger.alert("t", bad)
    assert len(ledger.audit_log(1)) == 0
    # failed mutation consumes its seq (claim-then-burn)
    with pytest.raises(BadSignalError):
        ledger.monitor("t", 1, safety_signal="nope")
    assert ledger.stats(2)["seq"] == 1
    # genuine rewind after advance raises bare, zero new rows
    ledger.monitor("t", 2)
    with pytest.raises(SeqOrderError):
        ledger.monitor("t", 1)
    with pytest.raises(SeqOrderError):
        ledger.alert("t", 2)
    assert ledger.stats(3)["seq"] == 2
    # gap seqs are allowed
    rec = ledger.monitor("t", 50)
    assert rec.watch_id == "swt-2"


def test_audit_shapes_and_leak_ban():
    """Audit rows have the right shape; banned keys and kinds fail closed."""
    ledger = AISafetyMonitoring()
    ledger.monitor("t", 1, config_digest=GOOD_DIGEST)
    ledger.alert("t", 2, alert_digest=GOOD_DIGEST)
    ledger.retire("t", 3)
    rows = ledger.audit_log(4)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["monitored", "alerted", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-safety-monitoring"
        assert r["version"] == "ai-safety-monitoring.v1"
    assert rows[0]["details"]["watch_id"] == "swt-1"
    assert rows[1]["details"]["alert_id"] == "sal-1"
    assert rows[2]["details"]["target_id"] == "t"
    # pinned vocab values remain emittable
    assert rows[1]["details"]["hazard_kind"] == "unsafe-output"
    assert rows[1]["details"]["observed_value"] == 0.0
    # banned raw keys fail closed at the builder
    with pytest.raises(AISafetyMonitoringError):
        ai_safety_monitoring_audit_event("monitored", 4, metric_stream="raw")
    with pytest.raises(AISafetyMonitoringError):
        ai_safety_monitoring_audit_event("alerted", 4, alert_payload="raw")
    with pytest.raises(AISafetyMonitoringError):
        ai_safety_monitoring_audit_event("monitored", 4, operator_id="op-1")
    with pytest.raises(AISafetyMonitoringError):
        ai_safety_monitoring_audit_event("monitored", 4, safety_report="raw")
    # bad kind / bad seq fail closed
    with pytest.raises(AuditKindError):
        ai_safety_monitoring_audit_event("nope", 4)
    with pytest.raises(SeqOrderError):
        ai_safety_monitoring_audit_event("monitored", True)


def test_views_stats_and_cross_instance_determinism():
    """Pure-read views/stats; digest pins deterministic across instances."""
    ops = []
    ledger = AISafetyMonitoring()
    w = ledger.monitor("t1", 1, safety_signal="harm-output-rate", threshold=0.1)
    a = ledger.alert("t1", 2, hazard_kind="policy-bypass", level="critical")
    ledger.monitor("t2", 3, safety_signal="refusal-rate")
    ledger.retire("t2", 4)
    ops.append((w, a))
    assert ledger.watch_record("swt-1", 5) == w
    assert ledger.alert_record("sal-1", 5) == a
    assert len(ledger.watches_for("t1", 5)) == 1
    assert len(ledger.alerts_for("t1", 5)) == 1
    assert ledger.watches_for("t2", 5) != ()
    assert ledger.alerts_for("t2", 5) == ()
    assert ledger.target_ids(5) == ("t1", "t2")
    assert ledger.watch_ids(5) == ("swt-1", "swt-2")
    assert ledger.alert_ids(5) == ("sal-1",)
    assert ledger.retired_ids(5) == ("t2",)
    st = ledger.stats(5)
    assert st["n_targets"] == 2
    assert st["n_watches"] == 2
    assert st["n_alerts"] == 1
    assert st["n_retired"] == 1
    assert st["version"] == "ai-safety-monitoring.v1"
    # unknown lookups
    with pytest.raises(UnknownRecordError):
        ledger.watch_record("swt-9", 5)
    with pytest.raises(UnknownRecordError):
        ledger.alert_record("sal-9", 5)
    # cross-instance digest determinism
    ledger2 = AISafetyMonitoring()
    w2 = ledger2.monitor("t1", 1, safety_signal="harm-output-rate", threshold=0.1)
    a2 = ledger2.alert("t1", 2, hazard_kind="policy-bypass", level="critical")
    assert w2.digest == w.digest
    assert a2.digest == a.digest
    # tamper in one instance does not leak into the other
    object.__setattr__(w2, "threshold", 7.7)
    assert ledger.verify("swt-1", 6).verdict == "verified"


def test_thread_read_smoke_and_frozenness():
    """Concurrent pure reads are safe; all records are frozen."""
    ledger = AISafetyMonitoring()
    w = ledger.monitor("t", 1)
    a = ledger.alert("t", 2)
    ev = ledger.evaluate("t", 3)

    def reader(n):
        for _ in range(50):
            assert ledger.verify(w.watch_id, 4).verdict == "verified"
            assert ledger.verify(a.alert_id, 4).verdict == "verified"
            assert ledger.evaluate("t", 4).posture == "safety-firing"
            ledger.watch_record("swt-1", 4)
            ledger.alert_record("sal-1", 4)
            ledger.watches_for("t", 4)
            ledger.alert_ids(4)
            ledger.stats(4)
            ledger.audit_log(4)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # frozen-ness across all record types
    for rec, field in ((w, "threshold"), (a, "observed_value"), (ev, "posture")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(rec, field, "x")


def test_main_subprocess_self_check():
    """main() self-check passes as a subprocess."""
    mod_path = Path(ai_safety_monitoring.__file__)
    proc = subprocess.run(
        [sys.executable, str(mod_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-safety-monitoring OK: monitor, alert, verify, evaluate, retire, pins, audit" in proc.stdout
