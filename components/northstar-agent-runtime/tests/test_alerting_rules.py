"""Tests for alerting_rules (Alertmanager/PagerDuty bookkeeping)."""

from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from alerting_rules import (
    ALERTING_RULES_SCHEMA,
    ALERTING_RULES_VERSION,
    CONDITIONS,
    CHANNELS,
    SEVERITIES,
    AlertingRules,
    BadNotificationError,
    BadRuleError,
    BadSilenceError,
    DuplicateRuleError,
    DuplicateSilenceError,
    SeqOrderError,
    SilenceStateError,
    UnknownRuleError,
    UnknownSilenceError,
    alerting_rules_audit_event,
)

MODULE = Path(__file__).resolve().parent.parent / "alerting_rules.py"


def _fresh() -> AlertingRules:
    return AlertingRules()


def _rule(ar: AlertingRules, rid: str = "r1", seq: int = 1):
    return ar.rule(rid, f"name-{rid}", "critical", "threshold", seq)


def test_version_and_schema_pins():
    assert ALERTING_RULES_VERSION == "alerting-rules.v1"
    assert ALERTING_RULES_SCHEMA == "northstar.alerting-rules.v1"
    assert SEVERITIES == ("critical", "warning", "info")
    assert len(CONDITIONS) == 4
    assert len(CHANNELS) == 5


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing",
        "__future__", "json", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_rule_roundtrip_and_verify():
    ar = _fresh()
    rec = _rule(ar)
    assert rec.verify()
    assert rec.rule_id == "r1"
    assert rec.severity == "critical"
    assert rec.condition == "threshold"
    assert ar.rule_record("r1") == rec
    assert ar.rule_ids() == ("r1",)


def test_rule_labels_sorted_and_pinned():
    ar = _fresh()
    rec = ar.rule("r1", "n", "warning", "heartbeat", 1,
                 labels=["team=oncall", "env=prod"])
    assert rec.labels == ("env=prod", "team=oncall")
    assert rec.verify()


def test_rule_bad_inputs():
    ar = _fresh()
    with pytest.raises(BadRuleError):
        ar.rule("", "n", "critical", "threshold", 1)
    with pytest.raises(BadRuleError):
        ar.rule("r1", "", "critical", "threshold", 2)
    with pytest.raises(BadRuleError):
        ar.rule("r1", "n", "fatal", "threshold", 3)
    with pytest.raises(BadRuleError):
        ar.rule("r1", "n", "critical", "bogus", 4)
    with pytest.raises(BadRuleError):
        ar.rule("r1", "n", "critical", "threshold", 5, labels=["noequals"])
    _rule(ar, seq=6)
    with pytest.raises(DuplicateRuleError):
        ar.rule("r1", "n", "critical", "threshold", 7)
    with pytest.raises(UnknownRuleError):
        ar.rule_record("nope")


def test_seq_ordering_and_failed_mutation_consumes_seq():
    ar = _fresh()
    _rule(ar, seq=1)
    with pytest.raises(SeqOrderError):
        ar.rule("r2", "n", "critical", "threshold", 1)  # rewind
    with pytest.raises(SeqOrderError):
        ar.rule("r2", "n", "critical", "threshold", True)  # bool
    with pytest.raises(BadRuleError):
        ar.rule("", "n", "critical", "threshold", 2)  # burns seq 2
    rec = ar.rule("r2", "n", "info", "heartbeat", 3)
    assert rec.seq == 3


def test_notify_happy_and_verify():
    ar = _fresh()
    _rule(ar)
    n = ar.notify("r1", 2, "pagerduty", "oncall@example.com")
    assert n.verify()
    assert not n.suppressed
    assert ar.notification(n.notification_id) == n
    assert ar.notifications_for("r1") == (n,)


def test_notify_bad_inputs():
    ar = _fresh()
    _rule(ar)
    with pytest.raises(UnknownRuleError):
        ar.notify("nope", 2, "email", "a@b.c")
    with pytest.raises(BadNotificationError):
        ar.notify("r1", 3, "carrier-pigeon", "a@b.c")
    with pytest.raises(BadNotificationError):
        ar.notify("r1", 4, "email", "   ")
    with pytest.raises(BadNotificationError):
        ar.notify("r1", 5, "email", "")


def test_silence_suppresses_but_never_refuses():
    ar = _fresh()
    _rule(ar)
    sil = ar.silence("s1", "r1", 2, 100, "deploy freeze")
    assert sil.verify()
    assert not sil.lifted
    n = ar.notify("r1", 3, "email", "team@example.com")
    assert n.suppressed
    assert n.verify()
    # other rule untouched
    ar.rule("r2", "n2", "warning", "heartbeat", 4)
    n2 = ar.notify("r2", 5, "sms", "+1-555-0000")
    assert not n2.suppressed


def test_silence_expiry_and_lift():
    ar = _fresh()
    _rule(ar)
    ar.silence("s1", "r1", 2, 10, "window")
    assert len(ar.active_silences("r1", 5)) == 1
    assert len(ar.active_silences("r1", 10)) == 0  # until_seq not > seq
    assert len(ar.active_silences("r1", 11)) == 0
    lifted = ar.lift_silence("s1", 3)
    assert lifted.lifted
    assert lifted.verify()
    assert len(ar.active_silences("r1", 4)) == 0
    with pytest.raises(SilenceStateError):
        ar.lift_silence("s1", 5)
    n = ar.notify("r1", 6, "webhook", "https://hooks/x")
    assert not n.suppressed


def test_silence_bad_inputs():
    ar = _fresh()
    _rule(ar)
    with pytest.raises(BadSilenceError):
        ar.silence("s1", "r1", 2, 2, "x")  # until_seq not after seq
    with pytest.raises(BadSilenceError):
        ar.silence("s1", "r1", 3, 50, "  ")
    with pytest.raises(UnknownRuleError):
        ar.silence("s1", "nope", 4, 50, "x")
    ar.silence("s1", "r1", 5, 50, "x")
    with pytest.raises(DuplicateSilenceError):
        ar.silence("s1", "r1", 6, 60, "x")
    with pytest.raises(UnknownSilenceError):
        ar.lift_silence("nope", 7)
    with pytest.raises(UnknownSilenceError):
        ar.silence_record("nope")


def test_audit_shapes_and_banned_keys():
    ar = _fresh()
    _rule(ar)
    ar.silence("s1", "r1", 2, 50, "freeze")
    n = ar.notify("r1", 3, "email", "team@example.com")
    kinds = {e["kind"] for e in ar.audit_log()}
    assert "alerting.rule-defined" in kinds
    assert "alerting.silenced" in kinds
    assert "alerting.suppressed" in kinds
    for e in ar.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "alerting-rules.v1"
        for banned in ("recipient", "message", "reason", "labels"):
            assert banned not in e["detail"]
    assert n.notification_id in ar.audit_log()[-1]["detail"]["notification_id"]
    with pytest.raises(Exception):
        alerting_rules_audit_event("bogus-kind", {}, 1)


def test_stats():
    ar = _fresh()
    _rule(ar)
    ar.silence("s1", "r1", 2, 50, "x")
    ar.notify("r1", 3, "email", "a@b.c")
    ar.notify("r1", 4, "email", "a@b.c")
    st = ar.stats()
    assert st["rules"] == 1
    assert st["notifications"] == 2
    assert st["suppressed"] == 2
    assert st["silences"] == 1


def test_thread_safety_smoke():
    ar = _fresh()
    for i in range(4):
        _rule(ar, rid=f"r{i}", seq=i + 1)

    def worker(i: int):
        base = 100 + i * 20
        ar.notify(f"r{i}", base, "webhook", "https://hooks/x")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert ar.stats()["notifications"] == 4


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, str(MODULE)], capture_output=True, text=True, timeout=30
    )
    assert r.returncode == 0, r.stderr
    assert "alerting-rules OK" in r.stdout
