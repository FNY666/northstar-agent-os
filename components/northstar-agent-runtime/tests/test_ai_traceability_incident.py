"""Tests for the ai_traceability_incident decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_traceability_incident
from ai_traceability_incident import (
    AI_TRACEABILITY_INCIDENT_VERSION,
    SCHEMA_PIN,
    CRITICAL_SEVERITY,
    AITraceabilityIncident,
    AITraceabilityIncidentError,
    AuditKindError,
    BadDigestError,
    BadFindingError,
    BadReasonError,
    BadTraceabilityIncidentError,
    BadTraceabilityIncidentKindError,
    BadSeverityError,
    INVESTIGATION_FINDINGS,
    POSTURES,
    RETIRE_REASONS,
    TRACEABILITY_INCIDENT_KINDS,
    RetiredTraceabilityIncidentError,
    SeqOrderError,
    UnknownRecordError,
    UnknownTraceabilityIncidentError,
    ai_traceability_incident_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_TRACEABILITY_INCIDENT_VERSION == "ai-traceability-incident.v1"
    assert SCHEMA_PIN == "northstar.ai-traceability-incident.v1"
    assert CRITICAL_SEVERITY == 75
    assert TRACEABILITY_INCIDENT_KINDS == (
        "lineage-gap",
        "provenance-loss",
        "record-tampering",
        "chain-of-custody-break",
        "reproducibility-failure",
        "version-lineage-drift",
        "traceability-blind-spot",
        "traceability-near-miss",
    )
    assert INVESTIGATION_FINDINGS == (
        "harm-confirmed",
        "harm-refuted",
        "root-cause-found",
        "contained",
        "inconclusive",
        "resolved",
    )
    assert POSTURES == (
        "unreported",
        "critical-open",
        "open",
        "under-review",
        "mitigated",
        "resolved",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_traceability_incident.__file__)
    tree = ast.parse(path.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed, node.module


def test_report_roundtrip_verify_and_frozenness():
    """report -> minted id, digest verifies, record is frozen."""
    ledger = AITraceabilityIncident()
    rec = ledger.report(
        "traceability-1",
        1,
        traceability_incident_kind="lineage-gap",
        severity=42,
        report_digest=GOOD_DIGEST,
    )
    assert rec.report_id == "tri-1"
    assert rec.traceability_incident_id == "traceability-1"
    assert rec.traceability_incident_kind == "lineage-gap"
    assert rec.severity == 42
    assert rec.report_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    with pytest.raises(Exception):
        rec.severity = 99  # frozen dataclass
    audit = ledger.audit_log(0)
    assert len(audit) == 1
    assert audit[0]["kind"] == "reported"
    assert audit[0]["details"]["traceability_incident_kind"] == "lineage-gap"


def test_report_bad_inputs_burn_seq_and_book_rejected():
    """Bad inputs fail closed: seq consumed, rejected row booked."""
    ledger = AITraceabilityIncident()
    cases = [
        ("", 1, {}, BadTraceabilityIncidentError),  # empty traceability incident id
        ("s1", 1, {"traceability_incident_kind": "nope"}, BadTraceabilityIncidentKindError),
        ("s1", 1, {"severity": -1}, BadSeverityError),
        ("s1", 1, {"severity": 101}, BadSeverityError),
        ("s1", 1, {"severity": True}, BadSeverityError),  # bool refused
        ("s1", 1, {"severity": 3.5}, BadSeverityError),
        ("s1", 1, {"report_digest": "bad"}, BadDigestError),
    ]
    seq = 1
    for traceability_incident_id, _, kwargs, exc in cases:
        with pytest.raises(exc):
            ledger.report(traceability_incident_id, seq, **kwargs)
        seq += 1
    # severity boundaries 0 and 100 are accepted
    r0 = ledger.report("s0", seq, severity=0)
    assert r0.severity == 0
    r100 = ledger.report("s100", seq + 1, severity=100)
    assert r100.severity == 100
    audit = ledger.audit_log(0)
    rejected = [r for r in audit if r["kind"] == "rejected"]
    assert len(rejected) == len(cases)
    # rewind raises bare without booking a new row
    before = len(audit)
    with pytest.raises(SeqOrderError):
        ledger.report("s9", 1)
    assert len(ledger.audit_log(0)) == before


def test_full_kind_vocabulary():
    """All 8 traceability-incident kinds are accepted over the vocabulary."""
    ledger = AITraceabilityIncident()
    seq = 1
    for kind in TRACEABILITY_INCIDENT_KINDS:
        rec = ledger.report(f"s-{kind}", seq, traceability_incident_kind=kind)
        assert rec.traceability_incident_kind == kind
        assert rec.verify()
        seq += 1
    assert ledger.stats(0)["n_traceability_incidents"] == len(TRACEABILITY_INCIDENT_KINDS)


def test_investigate_roundtrip_and_chain():
    """investigate mints inv-N ids, chains against the traceability incident."""
    ledger = AITraceabilityIncident()
    ledger.report("traceability-1", 1, traceability_incident_kind="provenance-loss", severity=60)
    inv1 = ledger.investigate(
        "traceability-1", 2, finding="root-cause-found", investigation_digest=GOOD_DIGEST
    )
    assert inv1.investigation_id == "inv-1"
    assert inv1.traceability_incident_id == "traceability-1"
    assert inv1.finding == "root-cause-found"
    assert inv1.verify()
    inv2 = ledger.investigate("traceability-1", 3, finding="resolved")
    assert inv2.investigation_id == "inv-2"
    audit = ledger.audit_log(0)
    assert [r["kind"] for r in audit] == ["reported", "investigated", "investigated"]
    # unknown traceability incident fails closed with a burned seq
    with pytest.raises(UnknownTraceabilityIncidentError):
        ledger.investigate("nope", 4)
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["details"]["rejected_kind"] == "UnknownTraceabilityIncidentError"


def test_investigate_refusals():
    """Bad finding/digest and retired incidents refuse with burned seqs."""
    ledger = AITraceabilityIncident()
    ledger.report("traceability-1", 1)
    with pytest.raises(BadFindingError):
        ledger.investigate("traceability-1", 2, finding="bogus")
    with pytest.raises(BadDigestError):
        ledger.investigate("traceability-1", 3, investigation_digest="zzz")
    with pytest.raises(BadTraceabilityIncidentError):
        ledger.investigate("", 4)
    # retired incident refuses
    ledger.report("traceability-2", 5)
    ledger.retire("traceability-2", 6)
    with pytest.raises(RetiredTraceabilityIncidentError):
        ledger.investigate("traceability-2", 7, finding="resolved")
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == 4
    kinds = {r["details"]["rejected_kind"] for r in rejected}
    assert kinds == {
        "BadFindingError",
        "BadDigestError",
        "BadTraceabilityIncidentError",
        "RetiredTraceabilityIncidentError",
    }
    # valid investigates still proceed after failures
    inv = ledger.investigate("traceability-1", 8, finding="contained")
    assert inv.verify()


def test_verify_semantics_tamper_as_data_and_read_purity():
    """verify is a pure read; tampering is reported as data, never raised."""
    ledger = AITraceabilityIncident()
    rec = ledger.report("traceability-1", 1, severity=10)
    inv = ledger.investigate("traceability-1", 2, finding="resolved")
    rep1 = ledger.verify(rec.report_id, 3)
    assert rep1.verdict == "verified"
    assert rep1.integrity_ok is True
    assert rep1.verify()
    rep2 = ledger.verify(inv.investigation_id, 4)
    assert rep2.verdict == "verified"
    # tamper is reported as data
    object.__setattr__(rec, "severity", 99)
    tampered = ledger.verify(rec.report_id, 5)
    assert tampered.verdict == "tampered"
    assert tampered.integrity_ok is False
    # pure read: same seq twice is fine, no audit rows, seq not consumed
    before = len(ledger.audit_log(0))
    a = ledger.verify(inv.investigation_id, 6)
    b = ledger.verify(inv.investigation_id, 6)
    assert a.verdict == b.verdict == "verified"
    assert len(ledger.audit_log(0)) == before
    assert ledger.stats(0)["seq"] == 2  # only the two mutations consumed seqs
    # unknown record refuses without consuming seq
    with pytest.raises(UnknownRecordError):
        ledger.verify("tri-999", 7)
    with pytest.raises(UnknownRecordError):
        ledger.verify("inv-999", 7)
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.report_id, True)  # bool seq refused


def test_evaluate_posture_math():
    """Ledger-rule posture derivation across all reachable postures."""
    ledger = AITraceabilityIncident()
    # critical-open: uninvestigated severity >= 75
    ledger.report("crit", 1, severity=75)
    assert ledger.evaluate("crit", 0).posture == "critical-open"
    # open: uninvestigated low severity
    ledger.report("low", 2, severity=10)
    assert ledger.evaluate("low", 0).posture == "open"
    # under-review: any inconclusive finding
    ledger.report("rev", 3)
    ledger.investigate("rev", 4, finding="inconclusive")
    assert ledger.evaluate("rev", 0).posture == "under-review"
    # open: harm-confirmed outranks under-review
    ledger.report("harm", 5)
    ledger.investigate("harm", 6, finding="harm-confirmed")
    assert ledger.evaluate("harm", 0).posture == "open"
    # mitigated: all contained / root-cause-found
    ledger.report("mit", 7)
    ledger.investigate("mit", 8, finding="contained")
    ledger.investigate("mit", 9, finding="root-cause-found")
    ev = ledger.evaluate("mit", 0)
    assert ev.posture == "mitigated"
    # resolved: all resolved / harm-refuted
    ledger.report("res", 10)
    ledger.investigate("res", 11, finding="resolved")
    ledger.investigate("res", 12, finding="harm-refuted")
    ev = ledger.evaluate("res", 0)
    assert ev.posture == "resolved"
    assert ev.n_reports == 1
    assert ev.n_investigations == 2
    assert ev.n_resolved == 1
    assert ev.integrity_ok is True
    assert ev.verify()
    # tallies: n_critical counts severity >= 75
    assert ledger.evaluate("crit", 0).n_critical == 1
    assert ledger.evaluate("low", 0).n_critical == 0


def test_evaluate_read_purity_and_unknown_refusal():
    """evaluate is a pure read; unknown traceability incident refuses."""
    ledger = AITraceabilityIncident()
    ledger.report("traceability-1", 1, severity=20)
    ledger.investigate("traceability-1", 2, finding="resolved")
    before = len(ledger.audit_log(0))
    a = ledger.evaluate("traceability-1", 3)
    b = ledger.evaluate("traceability-1", 3)
    assert a.posture == b.posture == "resolved"
    assert a.digest == b.digest  # deterministic
    assert len(ledger.audit_log(0)) == before
    with pytest.raises(UnknownTraceabilityIncidentError):
        ledger.evaluate("nope", 4)
    with pytest.raises(SeqOrderError):
        ledger.evaluate("traceability-1", "3")  # non-int seq refused


def test_retire_terminality():
    """retire is terminal; ids are never recycled; reads still work."""
    ledger = AITraceabilityIncident()
    ledger.report("traceability-1", 1)
    ret = ledger.retire("traceability-1", 2, reason="manual")
    assert ret.traceability_incident_id == "traceability-1"
    assert ret.reason == "manual"
    assert ret.verify()
    # post-retire mutations refuse
    with pytest.raises(RetiredTraceabilityIncidentError):
        ledger.report("traceability-1", 3)
    with pytest.raises(RetiredTraceabilityIncidentError):
        ledger.investigate("traceability-1", 4)
    # double retire refuses
    with pytest.raises(RetiredTraceabilityIncidentError):
        ledger.retire("traceability-1", 5)
    # bad reason fails closed
    ledger.report("traceability-2", 6)
    with pytest.raises(BadReasonError):
        ledger.retire("traceability-2", 7, reason="bogus")
    # reads still work after retirement
    assert ledger.evaluate("traceability-1", 0).posture == "open"
    assert len(ledger.reports_for("traceability-1", 0)) == 1
    assert ledger.retired_ids(0) == ("traceability-1",)
    # all four retire reasons accepted
    seq = 8
    for i, reason in enumerate(RETIRE_REASONS):
        ledger.report(f"r{i}", seq, severity=0)
        r = ledger.retire(f"r{i}", seq + 1, reason=reason)
        assert r.reason == reason
        seq += 2
    assert len(ledger.retired_ids(0)) == 5


def test_seq_discipline():
    """Strictly-increasing seqs: rewinds raise bare; malformed seqs refused."""
    ledger = AITraceabilityIncident()
    # genesis rewind: seq 0 rewinds the initial state and raises bare
    with pytest.raises(SeqOrderError):
        ledger.report("traceability-1", 0)
    assert len(ledger.audit_log(0)) == 0  # bare raise, no row
    rec = ledger.report("traceability-1", 1)
    assert rec.report_id == "tri-1"
    # rewind after progress raises bare
    with pytest.raises(SeqOrderError):
        ledger.report("traceability-1", 1)
    assert len(ledger.audit_log(0)) == 1  # still just the one report row
    # malformed seqs raise bare (no rejected row, seq shape check first)
    for bad in (True, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            ledger.report("traceability-2", bad)
    assert len(ledger.audit_log(0)) == 1
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(BadTraceabilityIncidentKindError):
        ledger.report("traceability-2", 2, traceability_incident_kind="nope")
    assert ledger.stats(0)["seq"] == 2
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == 1


def test_audit_shapes_leak_ban_and_bad_kind():
    """Audit rows carry schema/module/version/kind/seq/details; raw keys banned."""
    ledger = AITraceabilityIncident()
    rec = ledger.report("traceability-1", 1, traceability_incident_kind="provenance-loss")
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-traceability-incident"
    assert row["version"] == AI_TRACEABILITY_INCIDENT_VERSION
    assert row["kind"] == "reported"
    assert row["seq"] == 1
    assert row["details"]["report_id"] == rec.report_id
    # builder-level: banned raw keys rejected
    with pytest.raises(AITraceabilityIncidentError):
        ai_traceability_incident_audit_event(
            "reported", 2, report_id="tri-1", harm_description="raw text"
        )
    with pytest.raises(AITraceabilityIncidentError):
        ai_traceability_incident_audit_event(
            "investigated", 2, investigation_id="inv-1", traceability_report="raw"
        )
    # bad kind fails closed
    with pytest.raises(AuditKindError):
        ai_traceability_incident_audit_event("nope", 2)
    # digest pins of banned values remain emittable
    ok = ai_traceability_incident_audit_event(
        "reported", 2, report_id="tri-1", report_digest=GOOD_DIGEST
    )
    assert ok["details"]["report_digest"] == GOOD_DIGEST


def test_views_stats_and_cross_instance_determinism():
    """Views/stats behave; identical inputs pin identical digests across instances."""
    a = AITraceabilityIncident()
    b = AITraceabilityIncident()
    rec_a = a.report("traceability-1", 1, traceability_incident_kind="provenance-loss", severity=30)
    rec_b = b.report("traceability-1", 1, traceability_incident_kind="provenance-loss", severity=30)
    assert rec_a.digest == rec_b.digest  # deterministic pins
    inv_a = a.investigate("traceability-1", 2, finding="contained")
    inv_b = b.investigate("traceability-1", 2, finding="contained")
    assert inv_a.digest == inv_b.digest
    assert a.traceability_incident_record("tri-1", 0).digest == rec_a.digest
    assert a.investigation_record("inv-1", 0).finding == "contained"
    assert a.reports_for("traceability-1", 0)[0].report_id == "tri-1"
    assert a.investigations_for("traceability-1", 0)[0].investigation_id == "inv-1"
    assert a.traceability_incident_ids(0) == ("traceability-1",)
    assert a.report_ids(0) == ("tri-1",)
    assert a.investigation_ids(0) == ("inv-1",)
    assert a.retired_ids(0) == ()
    stats = a.stats(0)
    assert stats == {
        "n_traceability_incidents": 1,
        "n_reports": 1,
        "n_investigations": 1,
        "n_retired": 0,
        "seq": 2,
        "version": AI_TRACEABILITY_INCIDENT_VERSION,
    }
    with pytest.raises(UnknownRecordError):
        a.traceability_incident_record("tri-999", 0)


def test_main_self_check_and_thread_smoke():
    """main() runs clean as a subprocess; concurrent reads stay consistent."""
    result = subprocess.run(
        [sys.executable, ai_traceability_incident.__file__],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "ai-traceability-incident OK" in result.stdout
    ledger = AITraceabilityIncident()
    ledger.report("traceability-1", 1, severity=10)
    ledger.investigate("traceability-1", 2, finding="resolved")
    errors = []

    def reader():
        try:
            for _ in range(50):
                assert ledger.evaluate("traceability-1", 0).posture == "resolved"
                assert ledger.verify("tri-1", 0).verdict == "verified"
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
