"""Tests for the spec API of incident_response.py: triage / contain / recover.

Batch 47 pushed ``IncidentResponse`` with ``triage()`` / ``contain()`` /
``resolve()`` (the triage -> contain -> resolution lifecycle ledger).
This companion file covers the spec's named terminal API
``recover()`` -- the additive alias for ``resolve()`` -- plus the
triage/contain/recover lifecycle as the spec frames it.
"""

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


def test_spec_api_present():
    ledger = ir.IncidentResponse()
    assert callable(ledger.triage)
    assert callable(ledger.contain)
    assert callable(ledger.recover)


def test_recover_lifecycle_roundtrip():
    ledger = open_incident()
    d = digest("notes")
    ledger.triage("INC-001", "SEV2", 2, rationale_digest=d)
    ledger.contain("INC-001", "rollback", 3, detail_digest=d)
    rec = ledger.recover("INC-001", 4, outcome="resolved",
                         resolution_digest=d)
    assert rec.incident_id == "INC-001"
    assert rec.outcome == "resolved"
    assert rec.resolution_digest == d
    assert rec.verify()
    assert ledger.resolution_record("INC-001", 5).digest == rec.digest


def test_recover_default_outcome():
    ledger = open_incident()
    ledger.triage("INC-001", "SEV3", 2)
    rec = ledger.recover("INC-001", 3)
    assert rec.outcome == "resolved"


def test_recover_mitigated_outcome():
    ledger = open_incident()
    ledger.triage("INC-001", "SEV1", 2)
    ledger.contain("INC-001", "isolate", 3)
    rec = ledger.recover("INC-001", 4, outcome="mitigated")
    assert rec.outcome == "mitigated"
    status = ledger.status("INC-001", 5)
    assert status.resolved and status.outcome == "mitigated"


def test_recover_false_positive_outcome():
    ledger = open_incident()
    rec = ledger.recover("INC-001", 2, outcome="false-positive")
    assert rec.outcome == "false-positive"
    assert rec.verify()


def test_recover_verify_and_digest_stability():
    ledger = open_incident()
    rec = ledger.recover("INC-001", 2, outcome="resolved")
    assert rec.verify()
    d = rec.as_dict()
    assert d["schema"] == "northstar.incident-response.v1"
    assert d["version"] == "incident-response.v1"


def test_recover_terminality():
    ledger = open_incident()
    ledger.triage("INC-001", "SEV2", 2)
    ledger.recover("INC-001", 3)
    with pytest.raises(ir.ResolvedIncidentError):
        ledger.triage("INC-001", "SEV1", 4)
    with pytest.raises(ir.ResolvedIncidentError):
        ledger.contain("INC-001", "failover", 5)
    with pytest.raises(ir.ResolvedIncidentError):
        ledger.recover("INC-001", 6)


def test_recover_unknown_incident_fails_closed():
    ledger = ir.IncidentResponse()
    with pytest.raises(ir.UnknownIncidentError):
        ledger.recover("INC-NOPE", 1)
    # claim-then-burn: the failed mutation consumed seq 1 and booked a row
    rejected = [e for e in ledger.audit_log(2)
                if e["kind"] == "incident-response.rejected"]
    assert len(rejected) == 1
    assert rejected[0]["seq"] == 1


def test_recover_bad_outcome_refused():
    ledger = open_incident()
    with pytest.raises(ir.BadOutcomeError):
        ledger.recover("INC-001", 2, outcome="wontfix")


def test_recover_seq_rewind_raises_bare():
    ledger = open_incident()
    ledger.triage("INC-001", "SEV2", 2)
    with pytest.raises(ir.SeqOrderError):
        ledger.recover("INC-001", 2)
    with pytest.raises(ir.SeqOrderError):
        ledger.recover("INC-001", "3")
    # bare rewind consumes nothing and books no rejected row
    rejected = [e for e in ledger.audit_log(3)
                if e["kind"] == "incident-response.rejected"]
    assert rejected == []
    rec = ledger.recover("INC-001", 3)
    assert rec.verify()


def test_recover_audit_shape_and_leak_ban():
    ledger = open_incident()
    ledger.triage("INC-001", "SEV2", 2)
    ledger.contain("INC-001", "throttle", 3)
    ledger.recover("INC-001", 4, outcome="resolved")
    events = ledger.audit_log(5)
    resolved = [e for e in events
                if e["kind"] == "incident-response.resolved"]
    assert len(resolved) == 1
    for event in events:
        assert event["schema"] == "audit.ndjson/1"
        for key in event["detail"]:
            assert key not in ir._BANNED_AUDIT_KEYS


def test_recover_matches_resolve_semantics():
    via_recover = open_incident(incident_id="INC-A")
    via_resolve = open_incident(incident_id="INC-B")
    via_recover.triage("INC-A", "SEV2", 2)
    via_resolve.triage("INC-B", "SEV2", 2)
    rec = via_recover.recover("INC-A", 3, outcome="mitigated")
    res = via_resolve.resolve("INC-B", 3, outcome="mitigated")
    assert rec.as_dict()["outcome"] == res.as_dict()["outcome"]
    assert rec.verify() and res.verify()


def test_recover_incidents_isolated():
    ledger = open_incident(incident_id="INC-A", seq=1)
    ledger.open_response("INC-B", 2, service="checkout")
    ledger.triage("INC-A", "SEV1", 3)
    ledger.triage("INC-B", "SEV4", 4)
    ledger.recover("INC-A", 5)
    # INC-B is untouched by INC-A's recovery
    status = ledger.status("INC-B", 6)
    assert not status.resolved
    with pytest.raises(ir.UnknownIncidentError):
        ledger.resolution_record("INC-B", 7)


def test_recover_stats_counts():
    ledger = open_incident()
    ledger.triage("INC-001", "SEV2", 2)
    ledger.contain("INC-001", "revoke-credentials", 3)
    ledger.recover("INC-001", 4)
    stats = ledger.stats(5)
    assert stats["responses"] == 1
    assert stats["triages"] == 1
    assert stats["containments"] == 1
    assert stats["resolutions"] == 1


def test_main_subprocess_still_green():
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "incident-response OK" in result.stdout
