"""Tests for the ai_incident decision ledger (Simulated).

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

import ai_incident
from ai_incident import (
    AI_INCIDENT_VERSION,
    SCHEMA_PIN,
    CRITICAL_SEVERITY,
    AIIncident,
    AIIncidentError,
    AuditKindError,
    BadDigestError,
    BadFindingError,
    BadIncidentError,
    BadIncidentKindError,
    BadReasonError,
    BadSeverityError,
    INCIDENT_KINDS,
    INVESTIGATION_FINDINGS,
    POSTURES,
    RETIRE_REASONS,
    RetiredIncidentError,
    SeqOrderError,
    UnknownIncidentError,
    UnknownRecordError,
    ai_incident_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_INCIDENT_VERSION == "ai-incident.v1"
    assert SCHEMA_PIN == "northstar.ai-incident.v1"
    assert CRITICAL_SEVERITY == 75
    assert INCIDENT_KINDS == (
        "capability-misuse",
        "misalignment",
        "specification-gaming",
        "deceptive-behavior",
        "data-breach",
        "safety-incident",
        "security-breach",
        "near-miss",
    )
    assert INVESTIGATION_FINDINGS == (
        "harm-confirmed",
        "harm-refuted",
        "inconclusive",
        "mitigated",
        "escalated",
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
    path = Path(ai_incident.__file__)
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
    ledger = AIIncident()
    rec = ledger.report(
        "incident-1", 1, incident_kind="data-breach", severity=42,
        report_digest=GOOD_DIGEST,
    )
    assert rec.report_id == "rpt-1"
    assert rec.incident_id == "incident-1"
    assert rec.incident_kind == "data-breach"
    assert rec.severity == 42
    assert rec.report_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    with pytest.raises(Exception):
        rec.severity = 99  # frozen dataclass
    audit = ledger.audit_log(0)
    assert len(audit) == 1
    assert audit[0]["kind"] == "reported"
    assert audit[0]["details"]["incident_kind"] == "data-breach"


def test_report_bad_inputs_burn_seq_and_book_rejected():
    """Bad inputs fail closed: seq consumed, rejected row booked."""
    ledger = AIIncident()
    cases = [
        ("", 1, {}, BadIncidentError),                    # empty incident_id
        ("i1", 1, {"incident_kind": "nope"}, BadIncidentKindError),
        ("i1", 1, {"severity": -1}, BadSeverityError),
        ("i1", 1, {"severity": 101}, BadSeverityError),
        ("i1", 1, {"severity": True}, BadSeverityError),  # bool refused
        ("i1", 1, {"severity": 3.5}, BadSeverityError),
        ("i1", 1, {"report_digest": "bad"}, BadDigestError),
    ]
    seq = 1
    for incident_id, _, kwargs, exc in cases:
        with pytest.raises(exc):
            ledger.report(incident_id, seq, **kwargs)
        seq += 1
    # severity boundaries 0 and 100 are accepted
    r0 = ledger.report("i0", seq, severity=0)
    assert r0.severity == 0
    r100 = ledger.report("i100", seq + 1, severity=100)
    assert r100.severity == 100
    audit = ledger.audit_log(0)
    rejected = [r for r in audit if r["kind"] == "rejected"]
    assert len(rejected) == len(cases)
    assert all(r["details"]["rejected_kind"].endswith("Error") for r in rejected)


def test_full_incident_kind_vocabulary_accepted():
    """Every pinned incident kind books cleanly."""
    ledger = AIIncident()
    seq = 1
    for i, kind in enumerate(INCIDENT_KINDS):
        rec = ledger.report(f"inc-{i}", seq, incident_kind=kind, severity=5)
        assert rec.incident_kind == kind
        assert rec.verify()
        seq += 1
    assert ledger.stats(0)["n_reports"] == len(INCIDENT_KINDS)


def test_investigate_roundtrip_and_chain_and_full_finding_vocabulary():
    """investigate books minted ids; chainable; full finding vocabulary."""
    ledger = AIIncident()
    ledger.report("i1", 1, severity=10)
    seq = 2
    ids = []
    for finding in INVESTIGATION_FINDINGS:
        inv = ledger.investigate("i1", seq, finding=finding,
                                 investigation_digest=GOOD_DIGEST)
        assert inv.investigation_id == f"inv-{len(ids) + 1}"
        assert inv.incident_id == "i1"
        assert inv.finding == finding
        assert inv.verify()
        ids.append(inv.investigation_id)
        seq += 1
    with pytest.raises(Exception):
        inv.finding = "resolved"  # frozen dataclass
    audit = ledger.audit_log(0)
    assert [r["kind"] for r in audit] == ["reported"] + ["investigated"] * len(
        INVESTIGATION_FINDINGS
    )
    assert len(set(ids)) == len(INVESTIGATION_FINDINGS)


def test_investigate_refusals_unknown_retired_bad_finding_bad_digest():
    """investigate is fail-closed: unknown/retired/bad inputs refused."""
    ledger = AIIncident()
    with pytest.raises(UnknownIncidentError):
        ledger.investigate("nope", 1, finding="resolved")
    ledger.report("i1", 2, severity=10)
    with pytest.raises(BadFindingError):
        ledger.investigate("i1", 3, finding="guilty")
    with pytest.raises(BadDigestError):
        ledger.investigate("i1", 4, investigation_digest="nope")
    ledger.retire("i1", 5)
    with pytest.raises(RetiredIncidentError):
        ledger.investigate("i1", 6, finding="resolved")
    with pytest.raises(RetiredIncidentError):
        ledger.report("i1", 7, severity=1)
    audit = ledger.audit_log(0)
    rejected = [r for r in audit if r["kind"] == "rejected"]
    # unknown(1) + bad finding(1) + bad digest(1) + post-retire x2 = 5
    assert len(rejected) == 5


def test_verify_semantics_tamper_and_read_purity():
    """verify is a pure read; tamper reported as data; unknown refused."""
    import dataclasses

    ledger = AIIncident()
    rec = ledger.report("i1", 1, severity=10)
    inv = ledger.investigate("i1", 2, finding="resolved")
    for rid in (rec.report_id, inv.investigation_id):
        rep = ledger.verify(rid, 3)
        assert rep.verdict == "verified"
        assert rep.integrity_ok
        assert rep.verify()
    # tamper reported as data, never raised
    tampered = dataclasses.replace(rec, severity=99)
    ledger._reports[rec.report_id] = tampered
    rep = ledger.verify(rec.report_id, 4)
    assert rep.verdict == "tampered"
    assert not rep.integrity_ok
    ev = ledger.evaluate("i1", 5)
    assert not ev.integrity_ok  # tamper flips evaluate's integrity too
    with pytest.raises(UnknownRecordError):
        ledger.verify("rpt-999", 6)
    # read purity: same seq twice, no audit rows, no seq consumption
    a = ledger.verify(inv.investigation_id, 7)
    b = ledger.verify(inv.investigation_id, 7)
    assert a.digest == b.digest
    assert all(r["kind"] != "verified" for r in ledger.audit_log(0))


def test_evaluate_posture_math_and_precedence():
    """Posture math follows the documented precedence."""
    # critical-open: uninvestigated + severity >= 75
    l1 = AIIncident()
    l1.report("c1", 1, severity=90)
    assert l1.evaluate("c1", 2).posture == "critical-open"
    # open: uninvestigated + low severity
    l2 = AIIncident()
    l2.report("c2", 1, severity=10)
    assert l2.evaluate("c2", 2).posture == "open"
    # under-review: inconclusive/escalated outranks the rest
    l3 = AIIncident()
    l3.report("c3", 1, severity=10)
    l3.investigate("c3", 2, finding="inconclusive")
    assert l3.evaluate("c3", 3).posture == "under-review"
    l3.investigate("c3", 4, finding="resolved")
    assert l3.evaluate("c3", 5).posture == "under-review"
    # open: harm-confirmed outranks mitigated-only only if mixed
    l4 = AIIncident()
    l4.report("c4", 1, severity=10)
    l4.investigate("c4", 2, finding="harm-confirmed")
    assert l4.evaluate("c4", 3).posture == "open"
    # mitigated: all mitigated
    l5 = AIIncident()
    l5.report("c5", 1, severity=10)
    l5.investigate("c5", 2, finding="mitigated")
    l5.investigate("c5", 3, finding="mitigated")
    ev5 = l5.evaluate("c5", 4)
    assert ev5.posture == "mitigated"
    assert ev5.n_reports == 1 and ev5.n_investigations == 2
    # resolved: all resolved/harm-refuted
    l6 = AIIncident()
    l6.report("c6", 1, severity=99)
    l6.investigate("c6", 2, finding="resolved")
    ev6 = l6.evaluate("c6", 3)
    assert ev6.posture == "resolved"
    assert ev6.n_critical == 1 and ev6.n_resolved == 1
    assert ev6.integrity_ok


def test_evaluate_read_purity_and_unknown_incident():
    """evaluate is a pure read; unknown incidents raise."""
    ledger = AIIncident()
    ledger.report("i1", 1, severity=10)
    a = ledger.evaluate("i1", 2)
    b = ledger.evaluate("i1", 2)
    assert a.digest == b.digest
    assert all(r["kind"] not in ("evaluated",) for r in ledger.audit_log(0))
    with pytest.raises(UnknownIncidentError):
        ledger.evaluate("nope", 3)
    with pytest.raises(SeqOrderError):
        ledger.evaluate("i1", True)
    assert ledger.stats(0)["n_incidents"] == 1


def test_retire_terminality_and_id_non_recycling():
    """retire is terminal; ids never recycled; reads still work."""
    ledger = AIIncident()
    ledger.report("i1", 1, severity=10)
    ledger.investigate("i1", 2, finding="resolved")
    with pytest.raises(BadReasonError):
        ledger.retire("i1", 3, reason="nope")
    with pytest.raises(UnknownIncidentError):
        ledger.retire("nope", 4)
    ret = ledger.retire("i1", 5, reason="superseded")
    assert ret.verify()
    assert ledger.retired_ids(0) == ("i1",)
    with pytest.raises(RetiredIncidentError):
        ledger.retire("i1", 6)  # double retire
    # new report on retired id -> id NOT recycled, refused
    with pytest.raises(RetiredIncidentError):
        ledger.report("i1", 7, severity=1)
    # post-retire reads still work
    assert ledger.evaluate("i1", 8).posture == "resolved"
    assert ledger.incident_ids(0) == ("i1",)
    audit = ledger.audit_log(0)
    retired_rows = [r for r in audit if r["kind"] == "retired"]
    assert len(retired_rows) == 1
    assert retired_rows[0]["seq"] == 5


def test_seq_discipline_rewind_malformed_and_burn():
    """Rewinds raise bare; malformed seqs raise; burns consume seq."""
    ledger = AIIncident()
    ledger.report("i1", 1, severity=10)
    with pytest.raises(SeqOrderError):
        ledger.report("i2", 1)  # rewind: bare, zero rows
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 0
    for bad in (True, "2", 2.0, None):
        with pytest.raises(SeqOrderError):
            ledger.report("i2", bad)
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 0
    # failed mutation consumes its seq
    with pytest.raises(BadIncidentKindError):
        ledger.report("i2", 2, incident_kind="nope")
    # seq 2 is now burned; seq 3 works
    rec = ledger.report("i2", 3, severity=1)
    assert rec.report_id == "rpt-2"
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 1


def test_audit_shapes_leak_ban_and_bad_kind():
    """Audit rows have the fixed shape; banned keys raise; bad kinds raise."""
    ledger = AIIncident()
    rec = ledger.report("i1", 1, severity=10)
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-incident"
    assert row["version"] == "ai-incident.v1"
    assert row["kind"] == "reported"
    assert row["seq"] == 1
    assert row["details"]["report_id"] == rec.report_id
    assert row["details"]["severity"] == 10
    for banned in ("incident_description", "victim_identity", "forensic_data",
                   "harm_narrative", "reporter_identity", "timeline"):
        with pytest.raises(AIIncidentError):
            ai_incident_audit_event("reported", 9, **{banned: "raw"})
    with pytest.raises(AuditKindError):
        ai_incident_audit_event("bogus", 9)
    with pytest.raises(SeqOrderError):
        ai_incident_audit_event("reported", True)
    # pinned vocab values cross the boundary fine
    ok = ai_incident_audit_event("reported", 9, incident_kind="near-miss",
                                 severity=10, report_digest=GOOD_DIGEST)
    assert ok["details"]["incident_kind"] == "near-miss"


def test_digest_determinism_views_and_unknown_lookups():
    """Cross-instance digest determinism; views; unknown lookups fail closed."""
    a = AIIncident()
    b = AIIncident()
    ra = a.report("i1", 1, incident_kind="near-miss", severity=3,
                  report_digest=GOOD_DIGEST)
    rb = b.report("i1", 1, incident_kind="near-miss", severity=3,
                  report_digest=GOOD_DIGEST)
    assert ra.digest == rb.digest
    ia = a.investigate("i1", 2, finding="resolved")
    ib = b.investigate("i1", 2, finding="resolved")
    assert ia.digest == ib.digest
    ea = a.evaluate("i1", 3)
    eb = b.evaluate("i1", 3)
    assert ea.digest == eb.digest
    assert a.incident_record("rpt-1", 0) == ra
    assert a.investigation_record("inv-1", 0) == ia
    assert [r.report_id for r in a.reports_for("i1", 0)] == ["rpt-1"]
    assert [i.investigation_id for i in a.investigations_for("i1", 0)] == ["inv-1"]
    assert a.incident_ids(0) == ("i1",)
    assert a.report_ids(0) == ("rpt-1",)
    assert a.investigation_ids(0) == ("inv-1",)
    assert a.retired_ids(0) == ()
    with pytest.raises(UnknownRecordError):
        a.incident_record("rpt-999", 0)
    with pytest.raises(UnknownRecordError):
        a.investigation_record("inv-999", 0)


def test_thread_safety_frozen_records_and_main_via_subprocess():
    """8-thread read smoke; records frozen; main() subprocess self-check."""
    ledger = AIIncident()
    ledger.report("i1", 1, severity=10)
    ledger.investigate("i1", 2, finding="resolved")
    errors = []

    def reader():
        try:
            for _ in range(50):
                assert ledger.evaluate("i1", 0).posture == "resolved"
                assert ledger.stats(0)["n_reports"] == 1
                assert len(ledger.audit_log(0)) == 2
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    proc = subprocess.run(
        [sys.executable, "ai_incident.py"],
        cwd=Path(ai_incident.__file__).parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-incident OK" in proc.stdout
