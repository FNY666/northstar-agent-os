"""Tests for the ai_monitoring decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_monitoring
from ai_monitoring import (
    AI_MONITORING_VERSION,
    SCHEMA_PIN,
    MONITORED_METRICS,
    WATCH_CADENCES,
    ALERT_LEVELS,
    ALERT_STATUSES,
    POSTURES,
    RETIRE_REASONS,
    AIMonitoring,
    AIMonitoringError,
    AuditKindError,
    BadCadenceError,
    BadDigestError,
    BadLevelError,
    BadMetricError,
    BadObservedError,
    BadReasonError,
    BadStatusError,
    BadTargetError,
    BadThresholdError,
    RetiredTargetError,
    SeqOrderError,
    UnknownRecordError,
    UnknownTargetError,
    ai_monitoring_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_MONITORING_VERSION == "ai-monitoring.v1"
    assert SCHEMA_PIN == "northstar.ai-monitoring.v1"
    assert MONITORED_METRICS == (
        "error-rate",
        "latency-p99",
        "cost-per-task",
        "toxic-output-rate",
        "policy-violation-rate",
        "refusal-rate",
        "anomaly-score",
        "drift-score",
        "throughput",
        "queue-depth",
    )
    assert WATCH_CADENCES == ("realtime", "minute", "hourly", "daily")
    assert ALERT_LEVELS == ("info", "warning", "critical")
    assert ALERT_STATUSES == ("firing", "acknowledged", "resolved")
    assert POSTURES == (
        "unmonitored",
        "critical-firing",
        "firing",
        "warned",
        "covered",
        "quiet",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """The module imports stdlib names only (AST self-check)."""
    assert stdlib_only()
    assert ai_monitoring.stdlib_only()


def test_monitor_books_watch_with_pin():
    """monitor() books a watch, mints mon-N, digest pin verifies."""
    ledger = AIMonitoring()
    rec = ledger.monitor(
        "target-1",
        1,
        metric="error-rate",
        threshold=0.05,
        cadence="minute",
        config_digest=GOOD_DIGEST,
    )
    assert rec.monitor_id == "mon-1"
    assert rec.target_id == "target-1"
    assert rec.metric == "error-rate"
    assert rec.threshold == 0.05
    assert rec.cadence == "minute"
    assert rec.config_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify()


def test_alert_books_alert_with_pin():
    """alert() books an alert on a watched target, mints alr-N, pin verifies."""
    ledger = AIMonitoring()
    ledger.monitor("target-1", 1)
    rec = ledger.alert(
        "target-1",
        2,
        metric="error-rate",
        level="warning",
        observed_value=0.12,
        status="firing",
        alert_digest=GOOD_DIGEST,
    )
    assert rec.alert_id == "alr-1"
    assert rec.target_id == "target-1"
    assert rec.level == "warning"
    assert rec.observed_value == 0.12
    assert rec.status == "firing"
    assert rec.alert_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify()


def test_verify_reports_verified_and_tampered():
    """verify() pure-reads a digest pin; tampering flips the verdict as data."""
    ledger = AIMonitoring()
    rec = ledger.monitor("target-1", 1)
    rep = ledger.verify(rec.monitor_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    tampered = ledger.monitor_record(rec.monitor_id, 2).__class__(
        **{
            **rec.__dict__,
            "digest": "sha256:" + "00" * 32,
        }
    )
    assert tampered.verify() is False
    with pytest.raises(UnknownRecordError):
        ledger.verify("mon-999", 3)


def test_alert_fail_closed_unknown_and_retired_target():
    """alert() fails closed on unknown and retired targets, seq burned."""
    ledger = AIMonitoring()
    with pytest.raises(UnknownTargetError):
        ledger.alert("nope", 1)
    ledger.monitor("target-1", 2)
    ledger.retire("target-1", 3)
    with pytest.raises(RetiredTargetError):
        ledger.alert("target-1", 4)
    with pytest.raises(RetiredTargetError):
        ledger.monitor("target-1", 5)
    rows = ledger.audit_log(6)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 3
    assert ledger.stats(6)["seq"] == 5


def test_fail_closed_vocabulary_and_shape():
    """Bad vocabulary/shapes burn seq and book rejected rows; rewinds raise bare."""
    ledger = AIMonitoring()
    with pytest.raises(BadMetricError):
        ledger.monitor("target-1", 1, metric="vibes")
    with pytest.raises(BadCadenceError):
        ledger.monitor("target-1", 2, cadence="century")
    with pytest.raises(BadThresholdError):
        ledger.monitor("target-1", 3, threshold=True)
    with pytest.raises(BadDigestError):
        ledger.monitor("target-1", 4, config_digest="not-a-pin")
    ledger.monitor("target-1", 5)
    with pytest.raises(BadLevelError):
        ledger.alert("target-1", 6, level="catastrophic")
    with pytest.raises(BadStatusError):
        ledger.alert("target-1", 7, status="gone")
    with pytest.raises(BadObservedError):
        ledger.alert("target-1", 8, observed_value="high")
    with pytest.raises(BadTargetError):
        ledger.monitor("", 9)
    with pytest.raises(SeqOrderError):
        ledger.monitor("target-1", 9)
    rows = ledger.audit_log(10)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 8


def test_retire_and_views():
    """retire() terminates an id; views read without consuming seq."""
    ledger = AIMonitoring()
    ledger.monitor("target-1", 1)
    ledger.monitor("target-1", 2)
    ledger.alert("target-1", 3)
    ret = ledger.retire("target-1", 4, reason="decommissioned")
    assert ret.verify()
    assert ledger.retired_ids(5) == ("target-1",)
    assert ledger.monitor_ids(5) == ("mon-1", "mon-2")
    assert ledger.alert_ids(5) == ("alr-1",)
    assert ledger.target_ids(5) == ("target-1",)
    assert len(ledger.watches_for("target-1", 5)) == 2
    assert len(ledger.alerts_for("target-1", 5)) == 1
    assert ledger.monitor_record("mon-1", 5).target_id == "target-1"
    assert ledger.alert_record("alr-1", 5).target_id == "target-1"
    assert ledger.stats(5)["seq"] == 4


def test_evaluate_posture_ladder():
    """evaluate() derives posture critical-firing -> firing -> warned -> covered -> quiet."""
    ledger = AIMonitoring()
    ledger.monitor("quiet-t", 1)
    assert ledger.evaluate("quiet-t", 2).posture == "quiet"
    ledger.monitor("covered-t", 3)
    ledger.alert("covered-t", 4, status="resolved")
    assert ledger.evaluate("covered-t", 5).posture == "covered"
    ledger.monitor("warned-t", 6)
    ledger.alert("warned-t", 7, status="acknowledged")
    assert ledger.evaluate("warned-t", 8).posture == "warned"
    ledger.monitor("firing-t", 9)
    ledger.alert("firing-t", 10, level="warning", status="firing")
    assert ledger.evaluate("firing-t", 11).posture == "firing"
    ledger.monitor("critical-t", 12)
    ledger.alert("critical-t", 13, level="critical", status="firing")
    rep = ledger.evaluate("critical-t", 14)
    assert rep.posture == "critical-firing"
    assert rep.n_monitors == 1
    assert rep.n_alerts == 1
    assert rep.n_firing == 1
    assert rep.n_critical == 1
    assert rep.integrity_ok is True
    assert rep.verify()
    with pytest.raises(UnknownTargetError):
        ledger.evaluate("nope", 15)


def test_evaluate_is_pure_read():
    """evaluate()/verify() never consume seq and never write audit rows."""
    ledger = AIMonitoring()
    ledger.monitor("target-1", 1)
    ledger.alert("target-1", 2)
    before = ledger.stats(3)
    ev = ledger.evaluate("target-1", 99)
    assert ev.posture == "firing"
    rep = ledger.verify("mon-1", 100)
    assert rep.verdict == "verified"
    assert ledger.stats(101)["seq"] == before["seq"]
    kinds = [r["kind"] for r in ledger.audit_log(101)]
    assert kinds == ["monitored", "alerted"]


def test_audit_event_shape_and_banned_keys():
    """audit rows are schema-pinned; raw keys are banned; unknown kinds raise."""
    row = ai_monitoring_audit_event(
        "monitored", 1, monitor_id="mon-1", metric="error-rate"
    )
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-monitoring"
    assert row["version"] == AI_MONITORING_VERSION
    assert row["kind"] == "monitored"
    with pytest.raises(AIMonitoringError):
        ai_monitoring_audit_event("monitored", 2, metric_stream=[0.1, 0.2])
    with pytest.raises(AIMonitoringError):
        ai_monitoring_audit_event("alerted", 2, alert_payload=b"x")
    row2 = ai_monitoring_audit_event(
        "alerted", 3, observed_value=0.5, level="warning"
    )
    assert row2["details"]["observed_value"] == 0.5
    with pytest.raises(AuditKindError):
        ai_monitoring_audit_event("watched", 2)
    with pytest.raises(SeqOrderError):
        ai_monitoring_audit_event("monitored", True)
    ledger = AIMonitoring()
    ledger.monitor("target-1", 1)
    ledger.alert("target-1", 2)
    rows = ledger.audit_log(3)
    assert [r["kind"] for r in rows] == ["monitored", "alerted"]
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)


def test_frozen_records_and_thread_safety():
    """Records are frozen; concurrent monitor/alert bookings stay consistent."""
    import dataclasses

    ledger = AIMonitoring()
    rec = ledger.monitor("target-1", 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.threshold = 0.9  # type: ignore[misc]
    import itertools

    counter = itertools.count(2)
    errors: list = []

    def worker():
        try:
            for _ in range(10):
                s = next(counter)
                ledger.monitor("target-w", s)
        except SeqOrderError:
            pass
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    ledger2 = AIMonitoring()
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ledger2.stats(1000)["n_monitors"] <= 40


def test_main_self_check_runs_green():
    """The module's main() self-check passes as a subprocess."""
    path = Path(ai_monitoring.__file__)
    out = subprocess.run(
        [sys.executable, str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert "ai-monitoring OK" in out.stdout


def test_retire_edge_cases_and_digest_validation():
    """Double retire, unknown retire, bad reason, bad digests fail closed."""
    ledger = AIMonitoring()
    with pytest.raises(UnknownTargetError):
        ledger.retire("ghost", 1)
    ledger.monitor("target-1", 2)
    with pytest.raises(BadReasonError):
        ledger.retire("target-1", 3, reason="expired")
    ret = ledger.retire("target-1", 4)
    assert ret.verify()
    with pytest.raises(RetiredTargetError):
        ledger.retire("target-1", 5)
    with pytest.raises(BadDigestError):
        ledger.monitor("target-2", 6, config_digest="sha256:zzz")
    with pytest.raises(UnknownRecordError):
        ledger.monitor_record("mon-404", 7)
    with pytest.raises(UnknownRecordError):
        ledger.alert_record("alr-404", 7)
    rows = ledger.audit_log(8)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 4


def test_distinct_from_incident_lifecycle():
    """Monitoring ledger is distinct: watches/alerts, not incident reports."""
    ledger = AIMonitoring()
    assert not hasattr(ledger, "report")
    assert not hasattr(ledger, "investigate")
    assert callable(ledger.monitor)
    assert callable(ledger.alert)
    assert callable(ledger.verify)
    rec = ledger.monitor(
        "target-1", 1, metric="drift-score", threshold=0.3, cadence="hourly"
    )
    alr = ledger.alert(
        "target-1", 2, metric="drift-score", level="info", observed_value=0.31
    )
    assert rec.metric == "drift-score" == alr.metric
    rep = ledger.verify(alr.alert_id, 3)
    assert rep.verdict == "verified"
    assert rep.digest.startswith("sha256:")
