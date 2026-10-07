"""Tests for ai_ethics_monitoring: ethics-signal monitor/alert decision ledger."""

import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).parent.parent / "ai_ethics_monitoring.py"


def _load():
    spec = importlib.util.spec_from_file_location("ai_ethics_monitoring", _MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_ethics_monitoring"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def mod():
    return _load()


@pytest.fixture()
def led(mod):
    return mod.AIEthicsMonitoring()


# 1. pins / vocabularies ------------------------------------------------------
def test_pins_and_vocabularies(mod):
    assert mod.AI_ETHICS_MONITORING_VERSION == "ai-ethics-monitoring.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-ethics-monitoring.v1"
    assert mod.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(mod.ETHICS_SIGNALS) == 10
    assert len(mod.WATCH_CADENCES) == 4
    assert len(mod.ETHICS_CONCERN_KINDS) == 8
    assert len(mod.ALERT_LEVELS) == 3
    assert len(mod.ALERT_STATUSES) == 3
    assert len(mod.RETIRE_REASONS) == 4


# 2. stdlib-only ----------------------------------------------------------------
def test_stdlib_only(mod):
    assert mod.stdlib_only() is True


# 3. monitor roundtrip -----------------------------------------------------------
def test_monitor_roundtrip(mod, led):
    w = led.monitor("sys-1", 1, ethics_signal="fairness-violation-rate", threshold=0.1, cadence="hourly")
    assert w.record_id == "ewt-1"
    assert w.target_id == "sys-1"
    assert w.ethics_signal == "fairness-violation-rate"
    assert w.threshold == 0.1
    assert w.cadence == "hourly"
    assert w.verify() is True
    # frozen
    with pytest.raises(Exception):
        w.threshold = 9.9  # type: ignore
    rows = led.audit_log()
    assert rows[-1]["kind"] == "watched"
    assert rows[-1]["module"] == "ai-ethics-monitoring.v1"


# 4. monitor bad inputs: seq-burn + rejected rows --------------------------------
def test_monitor_bad_inputs(mod, led):
    base_rejected = lambda: sum(1 for r in led.audit_log() if r["kind"] == "rejected")
    start = base_rejected()
    cases = [
        ("", 1, {}),                       # bad target
        ("sys-1", 1, {"ethics_signal": "nope"}),  # bad signal
        ("sys-1", 1, {"cadence": "never"}),      # bad cadence
        ("sys-1", 1, {"threshold": -1.0}),        # bad threshold
        ("sys-1", 1, {"threshold": True}),       # bool threshold refused
    ]
    seq = 1
    for target, _s, kw in cases:
        with pytest.raises(mod.AIEthicsMonitoringError):
            led.monitor(target, seq, **kw)
        seq += 1
    assert base_rejected() - start == len(cases)
    # rewind raises bare with no new row
    led.monitor("sys-1", 100)
    rows_before = len(led.audit_log())
    with pytest.raises(mod.SeqOrderError):
        led.monitor("sys-2", 50)
    assert len(led.audit_log()) == rows_before


# 5. full signal vocabulary ------------------------------------------------------
def test_full_signal_vocabulary(mod, led):
    for i, sig in enumerate(mod.ETHICS_SIGNALS):
        w = led.monitor("sys-voc", 1 + i, ethics_signal=sig, threshold=0.01)
        assert w.ethics_signal == sig
        assert w.verify() is True
    assert len(led.watches_for("sys-voc")) == len(mod.ETHICS_SIGNALS)


# 6. alert roundtrip ---------------------------------------------------------------
def test_alert_roundtrip(mod, led):
    led.monitor("sys-1", 1)
    a = led.alert("sys-1", 2, concern_kind="privacy-violation", level="critical",
                  observed_value=0.9, status="firing")
    assert a.record_id == "eal-1"
    assert a.verify() is True
    with pytest.raises(Exception):
        a.status = "resolved"  # type: ignore
    rows = led.audit_log()
    assert rows[-1]["kind"] == "alerted"


# 7. alert refusal table ------------------------------------------------------------
def test_alert_refusals(mod, led):
    led.monitor("sys-1", 1)
    start = sum(1 for r in led.audit_log() if r["kind"] == "rejected")
    seq = 2
    with pytest.raises(mod.UnknownTargetError):
        led.alert("no-such-target", seq)
    seq += 1
    with pytest.raises(mod.BadConcernKindError):
        led.alert("sys-1", seq, concern_kind="nope")
    seq += 1
    with pytest.raises(mod.BadLevelError):
        led.alert("sys-1", seq, level="mega")
    seq += 1
    with pytest.raises(mod.BadStatusError):
        led.alert("sys-1", seq, status="maybe")
    seq += 1
    led.retire("sys-1", seq)
    seq += 1
    with pytest.raises(mod.RetiredTargetError):
        led.alert("sys-1", seq)
    assert sum(1 for r in led.audit_log() if r["kind"] == "rejected") - start == 5


# 8. verify semantics ---------------------------------------------------------------
def test_verify_semantics(mod, led):
    led.monitor("sys-1", 1)
    a = led.alert("sys-1", 2)
    rep = led.verify(a.record_id, 1)
    assert rep.verdict == "verified"
    assert rep.digest == a.digest()
    # tamper-as-data: mutating via object.__setattr__ is reported, never raised
    object.__setattr__(a, "level", "critical")
    rep2 = led.verify(a.record_id, 1)
    assert rep2.verdict == "tampered"
    # pure read: same-seq-twice ok, no new audit rows
    rows_before = len(led.audit_log())
    led.verify(a.record_id, 1)
    assert len(led.audit_log()) == rows_before
    # unknown refusal
    with pytest.raises(mod.UnknownRecordError):
        led.verify("eal-999", 1)


# 9. evaluate posture ladder ----------------------------------------------------------
def test_evaluate_posture_ladder(mod, led):
    # ethics-quiet: watched, no alerts
    led.monitor("t-quiet", 1)
    assert led.evaluate("t-quiet", 1).posture == "ethics-quiet"
    # ethics-covered: alert resolved
    led.monitor("t-covered", 2)
    led.alert("t-covered", 3, status="resolved")
    assert led.evaluate("t-covered", 1).posture == "ethics-covered"
    # ethics-warned: alert acknowledged
    led.monitor("t-warned", 4)
    led.alert("t-warned", 5, status="acknowledged")
    assert led.evaluate("t-warned", 1).posture == "ethics-warned"
    # ethics-firing: alert firing (non-critical)
    led.monitor("t-firing", 6)
    led.alert("t-firing", 7, level="warning", status="firing")
    assert led.evaluate("t-firing", 1).posture == "ethics-firing"
    # ethics-critical-firing outranks
    led.monitor("t-crit", 8)
    led.alert("t-crit", 9, level="critical", status="firing")
    ev = led.evaluate("t-crit", 1)
    assert ev.posture == "ethics-critical-firing"
    assert ev.critical_firing == 1
    assert ev.n_watches == 1 and ev.n_alerts == 1


# 10. evaluate purity + tamper flips integrity_ok --------------------------------------
def test_evaluate_purity_and_integrity(mod, led):
    led.monitor("sys-1", 1)
    a = led.alert("sys-1", 2)
    rows_before = len(led.audit_log())
    ev = led.evaluate("sys-1", 1)
    assert len(led.audit_log()) == rows_before
    assert ev.integrity_ok is True
    object.__setattr__(a, "observed_value", 123.0)
    ev2 = led.evaluate("sys-1", 1)
    assert ev2.integrity_ok is False
    # unknown target is still a pure read (quiet posture, no rows consumed)
    ev3 = led.evaluate("no-such", 1)
    assert ev3.posture == "ethics-quiet"
    assert len(led.audit_log()) == rows_before


# 11. retire terminality ----------------------------------------------------------------
def test_retire_terminality(mod, led):
    led.monitor("sys-1", 1)
    r = led.retire("sys-1", 2, reason="decommissioned")
    assert r.reason == "decommissioned"
    assert "sys-1" in led.retired_ids()
    # ids never recycled: a second retire is refused
    with pytest.raises(mod.RetiredTargetError):
        led.retire("sys-1", 3)
    # post-retire mutations refused
    with pytest.raises(mod.RetiredTargetError):
        led.monitor("sys-1", 4)
    with pytest.raises(mod.RetiredTargetError):
        led.alert("sys-1", 5)
    # reads still work
    assert led.evaluate("sys-1", 1).posture == "ethics-quiet"
    assert len(led.watches_for("sys-1")) == 1
    # bad reason refused
    led.monitor("sys-2", 6)
    with pytest.raises(mod.BadReasonError):
        led.retire("sys-2", 7, reason="because")


# 12. seq discipline ---------------------------------------------------------------------
def test_seq_discipline(mod, led):
    # genesis rewind bare with zero rows
    with pytest.raises(mod.SeqOrderError):
        led.monitor("sys-1", 0)
    assert len(led.audit_log()) == 0
    # malformed seqs
    for bad in (True, 1.5, "3", None):
        with pytest.raises(mod.SeqOrderError):
            led.monitor("sys-1", bad)  # type: ignore
    assert len(led.audit_log()) == 0
    # failed-mutation-consumes-seq: after a burned seq, reusing it raises bare
    led.monitor("sys-1", 10)
    with pytest.raises(mod.AIEthicsMonitoringError):
        led.alert("sys-1", 11, concern_kind="nope")
    with pytest.raises(mod.SeqOrderError):
        led.monitor("sys-2", 11)


# 13. audit shapes + leak ban + bad kind ---------------------------------------------------
def test_audit_shapes_and_leak_ban(mod, led):
    row = mod.ai_ethics_monitoring_audit_event("watched", 1, {"target_id": "x"})
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-ethics-monitoring.v1"
    assert row["kind"] == "watched"
    with pytest.raises(mod.AuditKindError):
        mod.ai_ethics_monitoring_audit_event("nope", 1, {})
    with pytest.raises(mod.AuditKeyError):
        mod.ai_ethics_monitoring_audit_event(
            "watched", 1, {"ethics_signal_stream": "raw"}
        )
    with pytest.raises(mod.AuditKeyError):
        mod.ai_ethics_monitoring_audit_event(
            "alerted", 1, {"victim_identity": "someone"}
        )
    with pytest.raises(mod.SeqOrderError):
        mod.ai_ethics_monitoring_audit_event("watched", -1, {})


# 14. views / stats / determinism -------------------------------------------------------------
def test_views_stats_and_determinism(mod, led):
    led.monitor("sys-1", 1, ethics_signal="bias-rate")
    led.alert("sys-1", 2, concern_kind="discriminatory-output")
    assert led.watch_record("ewt-1").record_id == "ewt-1"
    assert led.alert_record("eal-1").record_id == "eal-1"
    with pytest.raises(mod.UnknownRecordError):
        led.watch_record("ewt-999")
    st = led.stats()
    assert st["n_targets"] == 1 and st["n_watches"] == 1 and st["n_alerts"] == 1
    # cross-instance digest determinism
    other = mod.AIEthicsMonitoring()
    other.monitor("sys-1", 1, ethics_signal="bias-rate")
    other.alert("sys-1", 2, concern_kind="discriminatory-output")
    assert led.watch_record("ewt-1").digest() == other.watch_record("ewt-1").digest()
    assert led.alert_record("eal-1").digest() == other.alert_record("eal-1").digest()


# 15. thread smoke + main() subprocess ---------------------------------------------------------
def test_thread_smoke_and_main(mod):
    led = mod.AIEthicsMonitoring()
    led.monitor("sys-1", 1)
    for i in range(2, 10):
        led.alert("sys-1", i)
    errors: list = []

    def reader():
        try:
            for _ in range(50):
                led.evaluate("sys-1", 1)
                led.verify("eal-1", 1)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    proc = subprocess.run(
        [sys.executable, str(_MODULE_PATH)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0
    assert "ai-ethics-monitoring OK" in proc.stdout
