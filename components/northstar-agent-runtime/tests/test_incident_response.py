"""Tests for incident_response.py: triage / contain / resolve bookkeeping."""

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import incident_response as ir

HERE = Path(__file__).resolve().parent
MODULE = Path(__file__).resolve().parent.parent / "incident_response.py"


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def open_incident(ledger=None, incident_id="INC-001", seq=1):
    ledger = ledger or ir.IncidentResponse()
    ledger.open_response(incident_id, seq, service="payments")
    return ledger


def test_version_and_schema_pins():
    assert ir.INCIDENT_RESPONSE_VERSION == "incident-response.v1"
    assert ir.INCIDENT_RESPONSE_SCHEMA == "northstar.incident-response.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "json",
        "sys",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_open_roundtrip_and_verify():
    ledger = open_incident()
    record = ledger.response_record("INC-001", 2)
    assert record.incident_id == "INC-001"
    assert record.verify()
    assert ledger.incident_ids(3) == ("INC-001",)


def test_open_duplicate_and_bad_inputs_consume_seq():
    ledger = open_incident()
    with pytest.raises(ir.DuplicateIncidentError):
        ledger.open_response("INC-001", 2, service="payments")
    rejected = [e for e in ledger.audit_log(3) if e["kind"] == ir.KIND_REJECTED]
    assert len(rejected) == 1
    for bad_seq in (True, "x", -1):
        with pytest.raises(ir.SeqOrderError):
            ledger.open_response("BAD", bad_seq)
    with pytest.raises(ir.BadIncidentError):
        ledger.open_response("  ", 3)
    assert ledger.stats(4)["responses"] == 1


def test_triage_roundtrip_history_and_verify():
    ledger = open_incident()
    t1 = ledger.triage("INC-001", "SEV2", 2, rationale_digest=digest("r1"))
    t2 = ledger.triage("INC-001", "SEV1", 3)
    assert t1.triage_id != t2.triage_id
    assert t1.verify() and t2.verify()
    history = ledger.triage_history("INC-001", 4)
    assert [h.severity for h in history] == ["SEV2", "SEV1"]


def test_triage_bad_severity_and_unknown_incident():
    ledger = open_incident()
    with pytest.raises(ir.BadSeverityError):
        ledger.triage("INC-001", "SEV9", 2)
    with pytest.raises(ir.UnknownIncidentError):
        ledger.triage("NOPE", "SEV2", 3)
    with pytest.raises(ir.BadDigestError):
        ledger.triage("INC-001", "SEV2", 4, rationale_digest="not-a-digest")
    rejected = [e for e in ledger.audit_log(5) if e["kind"] == ir.KIND_REJECTED]
    assert len(rejected) == 3
    # raw text refused as a digest
    with pytest.raises(ir.BadDigestError):
        ledger.triage("INC-001", "SEV2", 5, rationale_digest="some text")


def test_contain_roundtrip_verify_and_vocabulary():
    ledger = open_incident()
    c1 = ledger.contain("INC-001", "rollback", 2, detail_digest=digest("d1"))
    c2 = ledger.contain("INC-001", "failover", 3)
    assert c1.containment_id != c2.containment_id
    assert c1.verify() and c2.verify()
    actions = ledger.containment_actions("INC-001", 4)
    assert [a.action for a in actions] == ["rollback", "failover"]
    with pytest.raises(ir.BadActionError):
        ledger.contain("INC-001", "restart-everything", 5)
    with pytest.raises(ir.UnknownIncidentError):
        ledger.contain("NOPE", "isolate", 6)


def test_resolve_roundtrip_outcomes_and_verify():
    ledger = open_incident()
    ledger.triage("INC-001", "SEV3", 2)
    record = ledger.resolve(
        "INC-001", 3, outcome="mitigated", resolution_digest=digest("r")
    )
    assert record.verify()
    assert record.outcome == "mitigated"
    read = ledger.resolution_record("INC-001", 4)
    assert read.outcome == "mitigated"
    with pytest.raises(ir.BadOutcomeError):
        open_incident().resolve("INC-001", 2, outcome="kinda-fixed")


def test_resolve_terminality():
    ledger = open_incident()
    ledger.resolve("INC-001", 2)
    with pytest.raises(ir.ResolvedIncidentError):
        ledger.resolve("INC-001", 3)
    with pytest.raises(ir.ResolvedIncidentError):
        ledger.triage("INC-001", "SEV1", 4)
    with pytest.raises(ir.ResolvedIncidentError):
        ledger.contain("INC-001", "isolate", 5)
    rejected = [e for e in ledger.audit_log(6) if e["kind"] == ir.KIND_REJECTED]
    assert len(rejected) == 3


def test_false_positive_outcome():
    ledger = open_incident()
    record = ledger.resolve("INC-001", 2, outcome="false-positive")
    assert record.outcome == "false-positive"
    assert record.verify()


def test_seq_discipline_rewind_bare_and_views():
    ledger = open_incident()
    ledger.triage("INC-001", "SEV2", 2)
    with pytest.raises(ir.SeqOrderError):
        ledger.triage("INC-001", "SEV2", 2)  # rewind: bare, no rejected row
    rejected = [e for e in ledger.audit_log(3) if e["kind"] == ir.KIND_REJECTED]
    assert rejected == []
    # pure-read views validate shape, consume nothing, book nothing
    before = ledger.stats(4)["audit_events"]
    ledger.status("INC-001", 4)
    ledger.triage_history("INC-001", 4)
    assert ledger.stats(5)["audit_events"] == before
    with pytest.raises(ir.UnknownIncidentError):
        ledger.status("NOPE", 6)
    with pytest.raises(ir.UnknownIncidentError):
        ledger.resolution_record("INC-001", 7)


def test_audit_shapes_and_leak_ban():
    ledger = open_incident()
    ledger.triage("INC-001", "SEV2", 2, rationale_digest=digest("r"))
    ledger.contain("INC-001", "isolate", 3)
    ledger.resolve("INC-001", 4)
    events = ledger.audit_log(5)
    kinds = {e["kind"] for e in events}
    assert kinds == {
        ir.KIND_OPENED,
        ir.KIND_TRIAGED,
        ir.KIND_CONTAINED,
        ir.KIND_RESOLVED,
    }
    for event in events:
        assert event["schema"] == ir.AUDIT_SCHEMA
        for key in event["detail"]:
            assert key not in ir._BANNED_AUDIT_KEYS
    # raw text can never be booked as a digest pin (fresh open incident)
    ledger.open_response("INC-002", 6, service="payments")
    with pytest.raises(ir.BadDigestError):
        ledger.triage("INC-002", "SEV2", 7, rationale_digest="raw summary text")
    with pytest.raises(ir.AuditKindError):
        ir.incident_response_audit_event("bogus-kind", 8)


def test_status_snapshot():
    ledger = open_incident()
    status = ledger.status("INC-001", 2)
    assert status.incident_id == "INC-001"
    assert status.triage_count == 0 and status.containment_count == 0
    assert status.latest_severity == "" and not status.resolved
    ledger.triage("INC-001", "SEV1", 3)
    ledger.contain("INC-001", "throttle", 4)
    ledger.resolve("INC-001", 5)
    status = ledger.status("INC-001", 6)
    assert status.triage_count == 1 and status.containment_count == 1
    assert status.latest_severity == "SEV1"
    assert status.resolved and status.outcome == "resolved"


def test_records_frozen_and_tamper_rejected():
    ledger = open_incident()
    record = ledger.response_record("INC-001", 2)
    with pytest.raises(Exception):
        record.incident_id = "X"  # type: ignore[misc]
    tampered = ledger.resolve("INC-001", 3)
    assert tampered.verify()
    object_bad = ir.ResolutionRecord(
        incident_id=tampered.incident_id,
        outcome="false-positive",
        resolution_digest=tampered.resolution_digest,
        seq=tampered.seq,
        digest=tampered.digest,
    )
    assert not object_bad.verify()


def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "incident-response OK" in result.stdout
