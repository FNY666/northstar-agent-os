"""Tests for the SOC operations workflow ledger (15 tests)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "soc.py"


def load_module():
    """Import the module standalone via importlib (frozen dataclasses
    need the module registered in sys.modules first)."""
    import importlib.util

    sys.modules.pop("soc", None)
    spec = importlib.util.spec_from_file_location("soc", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["soc"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def soc(mod):
    return mod.SOC()


def good_digest(label="evt"):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def test_version_and_schema_pins():
    mod = load_module()
    assert mod.VERSION == "soc.v1"
    assert mod.SCHEMA == "northstar.soc.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib", "re", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


def test_monitor_roundtrip_verify_and_views(soc, mod):
    rec = soc.monitor("m-endpoint", "endpoint", 1)
    assert rec.monitor_id == "m-endpoint"
    assert rec.scope == "endpoint"
    assert rec.verify()
    assert soc.monitor_record("m-endpoint", 2) is rec
    assert soc.monitor_ids(3) == ("m-endpoint",)
    assert soc.sensitivity("m-endpoint", 4) == "balanced"
    # duplicate refused fail-closed
    with pytest.raises(mod.DuplicateMonitorError):
        soc.monitor("m-endpoint", "network", 5)
    assert soc.stats(6)["rejected"] == 1


def test_monitor_bad_inputs_and_scope_vocabulary(soc, mod):
    for bad in (None, 1, True, b"x", "", "has space", "x" * 257):
        with pytest.raises((mod.BadIdError, mod.DuplicateMonitorError)):
            soc.monitor(bad, "email", soc.stats(0)["seq"] + 1)
    for scope in ("endpoint", "network", "identity", "cloud",
                  "application", "email"):
        soc.monitor(f"m-{scope}", scope, soc.stats(0)["seq"] + 1)
    for bad_scope in ("dns", "", None, 42):
        with pytest.raises(mod.BadScopeError):
            soc.monitor("m-bad", bad_scope, soc.stats(0)["seq"] + 1)
    assert soc.stats(0)["monitors"] == 6


def test_ingest_roundtrip_and_verify(soc):
    soc.monitor("m-net", "network", 1)
    evt = soc.ingest("m-net", "evt-1", 2, severity="critical",
                     event_digest=good_digest())
    assert evt.event_id == "evt-1"
    assert evt.monitor_id == "m-net"
    assert evt.severity == "critical"
    assert evt.event_pin == good_digest()
    assert evt.verify()
    assert soc.current_tier("evt-1", 3) == "L1"
    assert soc.events_for("m-net", 4) == ("evt-1",)
    for sev in ("low", "medium", "high", "critical"):
        soc.ingest("m-net", f"evt-{sev}", soc.stats(0)["seq"] + 1,
                   severity=sev)
    assert soc.stats(0)["events"] == 5


def test_ingest_refusals_and_seq_burn(soc, mod):
    soc.monitor("m-id", "identity", 1)
    # unknown monitor
    with pytest.raises(mod.UnknownMonitorError):
        soc.ingest("m-nope", "evt-x", 2)
    # bad severity
    with pytest.raises(mod.BadSeverityError):
        soc.ingest("m-id", "evt-x", 3, severity="urgent")
    # bad digest pin
    with pytest.raises(mod.BadDigestError):
        soc.ingest("m-id", "evt-x", 4, event_digest="not-a-pin")
    # bad event id
    with pytest.raises(mod.BadIdError):
        soc.ingest("m-id", "", 5)
    soc.ingest("m-id", "evt-1", 6)
    # duplicate event
    with pytest.raises(mod.DuplicateEventError):
        soc.ingest("m-id", "evt-1", 7)
    stats = soc.stats(8)
    assert stats["rejected"] == 5
    assert stats["seq"] == 7  # failed mutations consumed their seq


def test_escalate_lifecycle_to_incident(soc, mod):
    soc.monitor("m-cloud", "cloud", 1)
    soc.ingest("m-cloud", "evt-9", 2, severity="high")
    e1 = soc.escalate("evt-9", 3, "L2", reason="severity-bump")
    assert e1.esc_id == "esc-1"
    assert (e1.from_tier, e1.to_tier) == ("L1", "L2")
    assert e1.verify()
    e2 = soc.escalate("evt-9", 4, "L3")
    assert e2.esc_id == "esc-2"
    e3 = soc.escalate("evt-9", 5, "incident", reason="sla-breach")
    assert e3.esc_id == "esc-3"
    assert e3.verify()
    assert soc.current_tier("evt-9", 6) == "incident"
    assert soc.escalations_for("evt-9", 7) == ("esc-1", "esc-2", "esc-3")
    assert soc.queue_for_tier("incident", 8) == ("evt-9",)
    assert soc.queue_for_tier("L1", 9) == ()


def test_escalate_refusals_and_seq_burn(soc, mod):
    soc.monitor("m-app", "application", 1)
    soc.ingest("m-app", "evt-a", 2)
    # unknown event
    with pytest.raises(mod.UnknownEventError):
        soc.escalate("evt-nope", 3, "L2")
    # bad tier vocabulary
    with pytest.raises(mod.BadTierError):
        soc.escalate("evt-a", 4, "L4")
    # tier skip refused
    with pytest.raises(mod.TierOrderError):
        soc.escalate("evt-a", 5, "L3")
    # same tier refused
    with pytest.raises(mod.TierOrderError):
        soc.escalate("evt-a", 6, "L1")
    # regressive refused
    soc.escalate("evt-a", 7, "L2")
    with pytest.raises(mod.TierOrderError):
        soc.escalate("evt-a", 8, "L1")
    # bad reason refused
    with pytest.raises(mod.BadReasonError):
        soc.escalate("evt-a", 9, "L3", reason="vibes")
    for seq_v, tier in ((10, "L3"), (11, "incident")):
        soc.escalate("evt-a", seq_v, tier)
    # escalation past incident refused
    with pytest.raises(mod.TierOrderError):
        soc.escalate("evt-a", 12, "incident")
    stats = soc.stats(13)
    assert stats["escalations"] == 3
    assert stats["rejected"] == 7


def test_tune_roundtrip_and_verify(soc):
    soc.monitor("m-email", "email", 1)
    assert soc.sensitivity("m-email", 2) == "balanced"
    tun = soc.tune("m-email", 3, "high",
                   rationale_digest=good_digest("why"))
    assert tun.tun_id == "tun-1"
    assert tun.previous == "balanced"
    assert tun.sensitivity == "high"
    assert tun.rationale_pin == good_digest("why")
    assert tun.verify()
    assert soc.sensitivity("m-email", 4) == "high"
    assert soc.tunings_for("m-email", 5) == ("tun-1",)
    tun2 = soc.tune("m-email", 6, "aggressive")
    assert tun2.previous == "high"
    assert soc.sensitivity("m-email", 7) == "aggressive"


def test_tune_refusals_and_seq_burn(soc, mod):
    soc.monitor("m-net", "network", 1)
    # unknown monitor
    with pytest.raises(mod.UnknownMonitorError):
        soc.tune("m-nope", 2, "high")
    # bad sensitivity vocabulary
    with pytest.raises(mod.BadSensitivityError):
        soc.tune("m-net", 3, "maximum")
    # bad rationale digest
    with pytest.raises(mod.BadDigestError):
        soc.tune("m-net", 4, "low", rationale_digest="zzz")
    # same sensitivity refused
    with pytest.raises(mod.SameSensitivityError):
        soc.tune("m-net", 5, "balanced")
    stats = soc.stats(6)
    assert stats["rejected"] == 4
    assert stats["tunings"] == 0
    assert soc.sensitivity("m-net", 7) == "balanced"


def test_seq_discipline(soc, mod):
    soc.monitor("m-ep", "endpoint", 1)
    # rewind raises bare with no consumption and no rejected row
    with pytest.raises(mod.SeqOrderError):
        soc.monitor("m-other", "network", 1)
    assert soc.stats(2)["rejected"] == 0
    assert soc.stats(2)["seq"] == 1
    # malformed seqs raise bare
    for bad_seq in (True, "2", None, -1, 2.5):
        with pytest.raises(mod.SeqOrderError):
            soc.monitor("m-other", "network", bad_seq)
    # failed mutation consumes its seq
    with pytest.raises(mod.UnknownMonitorError):
        soc.tune("m-nope", 2, "high")
    assert soc.stats(3)["seq"] == 2
    assert soc.stats(3)["rejected"] == 1


def test_views_are_pure_reads(soc):
    soc.monitor("m-id", "identity", 1)
    soc.ingest("m-id", "evt-1", 2)
    soc.escalate("evt-1", 3, "L2")
    soc.tune("m-id", 4, "low")
    before = soc.audit_log(5)
    for _ in range(3):
        assert soc.current_tier("evt-1", 4) == "L2"
        assert soc.queue_for_tier("L2", 4) == ("evt-1",)
        assert soc.stats(4)["seq"] == 4
        assert soc.sensitivity("m-id", 4) == "low"
    # reads wrote nothing and consumed nothing
    assert soc.audit_log(4) == before
    assert soc.stats(4)["seq"] == 4


def test_audit_shapes_and_leak_ban():
    mod = load_module()
    soc = mod.SOC()
    soc.monitor("m-app", "application", 1)
    soc.ingest("m-app", "evt-1", 2)
    soc.escalate("evt-1", 3, "L2")
    soc.tune("m-app", 4, "high")
    rows = soc.audit_log(5)
    assert len(rows) == 4
    for row in rows:
        assert row["audit_version"] == "audit.ndjson/1"
        assert row["schema"] == "northstar.soc.v1"
        assert row["version"] == "soc.v1"
    kinds = [r["kind"] for r in rows]
    assert kinds == [
        "soc.monitor-registered",
        "soc.event-ingested",
        "soc.escalated",
        "soc.tuned",
    ]
    # rejected row shape
    with pytest.raises(mod.UnknownMonitorError):
        soc.ingest("m-nope", "evt-2", 5)
    rows = soc.audit_log(6)
    assert rows[-1]["kind"] == "soc.rejected"
    # bad audit kind refused
    with pytest.raises(mod.AuditKindError):
        mod.soc_audit_event("bogus", {}, 7)
    # raw content banned at the audit boundary
    for key in ("content", "payload", "rationale", "notes", "message",
                "hostname", "username", "evidence"):
        with pytest.raises(mod.AuditKindError):
            mod.soc_audit_event("event-ingested", {key: "x"}, 7)


def test_determinism_tamper_and_frozen():
    mod = load_module()
    a, b = mod.SOC(), mod.SOC()
    ra = a.monitor("m", "cloud", 1)
    rb = b.monitor("m", "cloud", 1)
    assert ra.digest == rb.digest
    ea = a.ingest("m", "evt-1", 2, severity="high")
    eb = b.ingest("m", "evt-1", 2, severity="high")
    assert ea.digest == eb.digest
    ta = a.tune("m", 3, "low")
    tb = b.tune("m", 3, "low")
    assert ta.digest == tb.digest
    # tamper breaks verify
    import dataclasses

    tampered = dataclasses.replace(ea, severity="low")
    assert not tampered.verify()
    assert ea.verify()
    # records are frozen
    rec = a.monitor("m2", "email", 4)
    with pytest.raises(AttributeError):
        rec.scope = "network"  # type: ignore[misc]


def test_concurrent_reads_and_main():
    mod = load_module()
    soc = mod.SOC()
    soc.monitor("m", "endpoint", 1)
    soc.ingest("m", "evt-1", 2)
    soc.escalate("evt-1", 3, "L2")
    errors = []

    def reader():
        try:
            for _ in range(50):
                soc.current_tier("evt-1", 3)
                soc.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "soc OK" in result.stdout
