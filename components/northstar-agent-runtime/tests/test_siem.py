"""Targeted tests for siem (SIEM decision ledger)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import siem
from siem import (
    SIEM,
    siem_audit_event,
    VERSION,
    SCHEMA,
    SOURCE_KINDS,
    EVENT_KINDS,
    SEVERITIES,
    RULES,
    VERDICTS,
    CHANNELS,
    ALERT_SEVERITIES,
    SourceRecord,
    EventRecord,
    CorrelationRecord,
    AlertRecord,
    SIEMError,
    BadSourceError,
    DuplicateSourceError,
    UnknownSourceError,
    BadSourceKindError,
    BadEventError,
    UnknownEventError,
    BadEventKindError,
    BadSeverityError,
    BadRuleError,
    UnknownCorrelationError,
    BadVerdictError,
    BadChannelError,
    BadDigestError,
    SeqOrderError,
    AuditKindError,
)

MODULE_PATH = Path(siem.__file__)
STDLIB_OK = {
    "__future__", "hashlib", "json", "threading", "dataclasses",
    "typing", "canonical_json",
}

PIN = "sha256:" + "ab" * 32


def new_siem():
    s = SIEM()
    s.register_source("src1", 1, source_kind="edr")
    return s


def new_full():
    s = new_siem()
    s.ingest("src1", "auth-failure", 2, severity="low")
    s.ingest("src1", "auth-failure", 3, severity="high")
    return s


# 1. pins
def test_version_schema_pins():
    assert VERSION == "siem.v1"
    assert SCHEMA == "northstar.siem.v1"
    assert SIEM().stats()["schema"] == SCHEMA
    assert len(SOURCE_KINDS) == 7 and "syslog" in SOURCE_KINDS
    assert len(EVENT_KINDS) == 10 and "auth-failure" in EVENT_KINDS
    assert SEVERITIES == ("info", "low", "medium", "high", "critical")
    assert len(RULES) == 6 and "brute-force" in RULES
    assert VERDICTS == ("match", "no-match", "inconclusive")
    assert len(CHANNELS) == 5 and "pagerduty" in CHANNELS
    assert ALERT_SEVERITIES == ("low", "medium", "high", "critical")


# 2. stdlib only
def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_OK, imports - STDLIB_OK


# 3. register_source roundtrip
def test_register_source_roundtrip():
    s = SIEM()
    rec = s.register_source("fw-01", 1, source_kind="firewall")
    assert isinstance(rec, SourceRecord)
    assert rec.source_id == "fw-01"
    assert rec.source_kind == "firewall"
    assert rec.verify()
    assert s.source_record("fw-01") == rec
    assert s.source_ids() == ("fw-01",)
    rows = s.audit_log()
    assert rows[0]["kind"] == "source-registered"
    assert rows[0]["schema"] == "audit.ndjson/1"


# 4. duplicate + bad inputs + seq-burn
def test_register_source_bad_inputs():
    s = SIEM()
    s.register_source("a", 1)
    with pytest.raises(DuplicateSourceError):
        s.register_source("a", 2)
    n_rejected = 1
    bad = [("", 3), ("  ", 4), (None, 5), (123, 6), ("x" * 129, 7), (True, 8)]
    for src, seq in bad:
        with pytest.raises(BadSourceError):
            s.register_source(src, seq)
        n_rejected += 1
    with pytest.raises(BadSourceKindError):
        s.register_source("b", 9, source_kind="nope")
    n_rejected += 1
    # every failed mutation burned its seq and booked a rejected row
    rows = s.audit_log()
    assert len([r for r in rows if r["kind"] == "rejected"]) == n_rejected
    # next free seq is 10
    s.register_source("b", 10)
    assert s.source_ids() == ("a", "b")


# 5. ingest roundtrip
def test_ingest_roundtrip():
    s = new_siem()
    rec = s.ingest("src1", "anomalous-egress", 2, event_digest=PIN,
                   severity="critical")
    assert isinstance(rec, EventRecord)
    assert rec.event_id == "evt-1"
    assert rec.source_id == "src1"
    assert rec.event_digest == PIN
    assert rec.verify()
    assert s.event_record("evt-1") == rec
    assert s.event_ids() == ("evt-1",)
    assert s.events_for("src1") == ("evt-1",)


# 6. ingest bad-input table + seq-burn
def test_ingest_bad_inputs():
    s = new_siem()
    n_rejected = 0
    with pytest.raises(UnknownSourceError):
        s.ingest("nope", "auth-failure", 2)
    n_rejected += 1
    with pytest.raises(BadEventKindError):
        s.ingest("src1", "weird-kind", 3)
    n_rejected += 1
    with pytest.raises(BadSeverityError):
        s.ingest("src1", "auth-failure", 4, severity="extreme")
    n_rejected += 1
    with pytest.raises(BadDigestError):
        s.ingest("src1", "auth-failure", 5, event_digest="raw-text-not-a-pin")
    n_rejected += 1
    with pytest.raises(BadDigestError):
        s.ingest("src1", "auth-failure", 6, event_digest=12345)
    n_rejected += 1
    rows = s.audit_log()
    assert len([r for r in rows if r["kind"] == "rejected"]) == n_rejected
    # raw payloads are refused by construction: no parameter takes them
    rec = s.ingest("src1", "port-scan", 7, severity="high")
    assert rec.event_id == "evt-1" and rec.verify()


# 7. correlate roundtrip
def test_correlate_roundtrip():
    s = new_full()
    cor = s.correlate("brute-force", ["evt-1", "evt-2"], 4, verdict="match")
    assert isinstance(cor, CorrelationRecord)
    assert cor.correlation_id == "cor-1"
    assert cor.rule == "brute-force"
    assert cor.event_ids == ("evt-1", "evt-2")
    assert cor.verdict == "match"
    assert cor.verify()
    assert s.correlation_record("cor-1") == cor
    assert s.correlation_ids() == ("cor-1",)


# 8. correlate refusals
def test_correlate_bad_inputs():
    s = new_full()
    n_rejected = 0
    with pytest.raises(BadRuleError):
        s.correlate("no-such-rule", ["evt-1"], 4)
    n_rejected += 1
    with pytest.raises(UnknownEventError):
        s.correlate("brute-force", ["evt-1", "evt-99"], 5)
    n_rejected += 1
    with pytest.raises(BadEventError):
        s.correlate("brute-force", [], 6)
    n_rejected += 1
    with pytest.raises(BadEventError):
        s.correlate("brute-force", ["evt-1", "evt-1"], 7)
    n_rejected += 1
    with pytest.raises(BadEventError):
        s.correlate("brute-force", "evt-1", 8)
    n_rejected += 1
    with pytest.raises(BadVerdictError):
        s.correlate("brute-force", ["evt-1"], 9, verdict="fired-hard")
    n_rejected += 1
    rows = s.audit_log()
    assert len([r for r in rows if r["kind"] == "rejected"]) == n_rejected
    cor = s.correlate("lateral-chain", ("evt-2",), 10, verdict="inconclusive")
    assert cor.verify() and s.correlation_ids() == ("cor-1",)


# 9. alert roundtrip + channel vocabulary
def test_alert_roundtrip():
    s = new_full()
    s.correlate("brute-force", ["evt-1", "evt-2"], 4, verdict="match")
    recs = []
    for i, channel in enumerate(CHANNELS):
        recs.append(s.alert("cor-1", 5 + i, channel, "high"))
    assert [r.alert_id for r in recs] == [f"alr-{i+1}" for i in range(5)]
    assert all(r.verify() for r in recs)
    assert s.alerts_for("cor-1") == tuple(f"alr-{i+1}" for i in range(5))
    rows = s.audit_log()
    assert rows[-1]["kind"] == "alert-raised"
    assert rows[-1]["detail"]["channel"] == "ticket"


# 10. alert refusals
def test_alert_bad_inputs():
    s = new_full()
    s.correlate("brute-force", ["evt-1"], 4)
    n_rejected = 0
    with pytest.raises(UnknownCorrelationError):
        s.alert("cor-99", 5, "siem", "high")
    n_rejected += 1
    with pytest.raises(BadChannelError):
        s.alert("cor-1", 6, "sms", "high")
    n_rejected += 1
    with pytest.raises(BadSeverityError):
        s.alert("cor-1", 7, "siem", "extreme")
    n_rejected += 1
    rows = s.audit_log()
    assert len([r for r in rows if r["kind"] == "rejected"]) == n_rejected
    a = s.alert("cor-1", 8, "slack", "critical")
    assert a.verify()


# 11. seq discipline
def test_seq_discipline():
    s = new_siem()
    s.ingest("src1", "port-scan", 2)
    # rewind raises bare: no rejected row, no seq consumption
    with pytest.raises(SeqOrderError):
        s.ingest("src1", "port-scan", 2)
    with pytest.raises(SeqOrderError):
        s.ingest("src1", "port-scan", 1)
    rows = s.audit_log()
    assert not [r for r in rows if r["kind"] == "rejected"]
    # malformed seqs raise bare too
    for bad in (True, -1, "3", 2.5, None):
        with pytest.raises(SeqOrderError):
            s.ingest("src1", "port-scan", bad)
    assert not [r for r in s.audit_log() if r["kind"] == "rejected"]
    # failed mutation consumes its seq
    with pytest.raises(BadEventKindError):
        s.ingest("src1", "nope", 3)
    with pytest.raises(SeqOrderError):
        s.ingest("src1", "port-scan", 3)
    s.ingest("src1", "port-scan", 4)


# 12. view read-purity
def test_view_read_purity():
    s = new_full()
    before = s.stats()
    s.source_record("src1")
    s.event_record("evt-1")
    s.source_ids()
    s.event_ids()
    s.events_for("src1")
    s.audit_log()
    assert s.stats() == before
    # views consumed no seq and wrote no audit rows
    s.ingest("src1", "service-crash", 4)
    assert s.stats()["events"] == 3
    with pytest.raises(UnknownSourceError):
        s.source_record("missing")
    with pytest.raises(UnknownEventError):
        s.event_record("evt-99")
    with pytest.raises(UnknownCorrelationError):
        s.correlation_record("cor-99")


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    s = new_siem()
    ev = siem_audit_event("event-ingested", {"event_id": "evt-1"})
    assert ev["kind"] == "event-ingested"
    assert ev["schema"] == "audit.ndjson/1"
    for banned in ("payload", "raw", "message", "command", "packet", "secret"):
        with pytest.raises(BadDigestError):
            siem_audit_event("event-ingested", {banned: "x"})
    with pytest.raises(AuditKindError):
        siem_audit_event("hacked")
    # banned keys also rejected at the _emit level
    with pytest.raises(BadDigestError):
        s._emit("event-ingested", {"payload": "x"})
    # all ledger audit rows carry the schema pin
    s.ingest("src1", "data-access", 2)
    assert all(r["schema"] == "audit.ndjson/1" for r in s.audit_log())


# 14. determinism, tamper, frozen, threads
def test_determinism_tamper_threads():
    a, b = SIEM(), SIEM()
    a.register_source("fw", 1, source_kind="firewall")
    b.register_source("fw", 1, source_kind="firewall")
    a.ingest("fw", "port-scan", 2)
    b.ingest("fw", "port-scan", 2)
    assert a.event_record("evt-1").digest == b.event_record("evt-1").digest
    rec = a.event_record("evt-1")
    object.__setattr__(rec, "severity", "critical")
    assert not rec.verify()
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = "low"  # type: ignore[misc]
    errs = []
    def reader():
        try:
            for _ in range(50):
                a.event_record("evt-1")
                a.stats()
                a.audit_log()
        except Exception as e:  # pragma: no cover
            errs.append(e)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs


# 15. main() self-check
def test_main():
    r = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, cwd=str(MODULE_PATH.parent),
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == (
        "siem OK: register, ingest, correlate, alert, pins"
    )
