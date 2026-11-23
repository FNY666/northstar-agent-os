"""Tests for the ai_compliance decision ledger (Simulated).

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

import ai_compliance
from ai_compliance import (
    AI_COMPLIANCE_VERSION,
    SCHEMA_PIN,
    ASSESSMENT_VERDICTS,
    AICompliance,
    AIComplianceError,
    AuditKindError,
    BadComplianceKindError,
    BadDigestError,
    BadReasonError,
    BadSeverityError,
    BadSystemError,
    BadVerdictError,
    COMPLIANCE_KINDS,
    POSTURES,
    RETIRE_REASONS,
    RetiredSystemError,
    SeqOrderError,
    UnknownAssessmentError,
    UnknownSystemError,
    ai_compliance_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_COMPLIANCE_VERSION == "ai-compliance.v1"
    assert SCHEMA_PIN == "northstar.ai-compliance.v1"
    assert COMPLIANCE_KINDS == (
        "regulatory-compliance",
        "data-governance",
        "safety-standards",
        "ethical-guidelines",
        "audit-readiness",
        "risk-management",
        "disclosure-obligations",
        "incident-reporting",
    )
    assert ASSESSMENT_VERDICTS == (
        "compliant",
        "partially-compliant",
        "non-compliant",
        "inconclusive",
        "not-assessed",
    )
    assert POSTURES == (
        "unassessed",
        "non-compliant",
        "contested",
        "partially-compliant",
        "compliant",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """The module imports stdlib names only (AST check)."""
    assert stdlib_only()
    tree = ast.parse(Path(ai_compliance.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                root = name.split(".")[0]
                assert root in {
                    "hashlib",
                    "json",
                    "threading",
                    "dataclasses",
                    "typing",
                    "__future__",
                    "ast",
                    "pathlib",
                    "canonical_json",
                }, root


def test_assess_roundtrip():
    """assess() books a frozen, self-verifying record with minted asm-N id."""
    ledger = AICompliance()
    rec = ledger.assess(
        "sys-1",
        1,
        compliance_kind="data-governance",
        verdict="compliant",
        severity=10,
        assessment_digest=GOOD_DIGEST,
    )
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.compliance_kind == "data-governance"
    assert rec.verdict == "compliant"
    assert rec.severity == 10
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    with pytest.raises(AttributeError):
        rec.verdict = "non-compliant"  # frozen
    # default arguments
    rec2 = ledger.assess("sys-1", 2)
    assert rec2.assessment_id == "asm-2"
    assert rec2.compliance_kind == "regulatory-compliance"
    assert rec2.verdict == "not-assessed"
    assert rec2.severity == 0
    assert rec2.assessment_digest == ""
    assert rec2.verify()
    # first assess registers the system
    assert ledger.system_ids(3) == ("sys-1",)
    # audit row emitted
    kinds = [row["kind"] for row in ledger.audit_log(4)]
    assert kinds == ["assessed", "assessed"]
    row = ledger.audit_log(4)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-compliance"
    assert row["version"] == AI_COMPLIANCE_VERSION


def test_assess_bad_inputs():
    """Bad inputs burn the seq and book an ai-compliance.rejected row."""
    ledger = AICompliance()
    cases = [
        ("", 1, "regulatory-compliance", "compliant", 0, GOOD_DIGEST, BadSystemError),
        (None, 1, "regulatory-compliance", "compliant", 0, GOOD_DIGEST, BadSystemError),
        (True, 1, "regulatory-compliance", "compliant", 0, GOOD_DIGEST, BadSystemError),
        ("sys", 2, "no-such-kind", "compliant", 0, GOOD_DIGEST, BadComplianceKindError),
        ("sys", 2, "regulatory-compliance", "bogus", 0, GOOD_DIGEST, BadVerdictError),
        ("sys", 2, "regulatory-compliance", "compliant", -1, GOOD_DIGEST, BadSeverityError),
        ("sys", 2, "regulatory-compliance", "compliant", 101, GOOD_DIGEST, BadSeverityError),
        ("sys", 2, "regulatory-compliance", "compliant", True, GOOD_DIGEST, BadSeverityError),
        ("sys", 2, "regulatory-compliance", "compliant", 1.5, GOOD_DIGEST, BadSeverityError),
        ("sys", 2, "regulatory-compliance", "compliant", 0, "nope", BadDigestError),
        ("sys", 2, "regulatory-compliance", "compliant", 0, "sha256:zz", BadDigestError),
    ]
    seq = 1
    rejected = 0
    for system_id, _s, kind, verdict, severity, digest, exc in cases:
        with pytest.raises(exc):
            ledger.assess(system_id, seq, compliance_kind=kind, verdict=verdict,
                          severity=severity, assessment_digest=digest)
        rejected += 1
        seq += 1
        # seq was burned even though the mutation failed
        with pytest.raises(SeqOrderError):
            ledger.assess("sys", seq - 1, compliance_kind="data-governance")
        seq += 0
    # severity boundaries accepted
    ledger.assess("sys", seq, severity=0)
    ledger.assess("sys", seq + 1, severity=100)
    rows = ledger.audit_log(seq + 2)
    rejected_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected_rows) == rejected
    for r in rejected_rows:
        assert r["module"] == "ai-compliance"
        assert "rejected_kind" in r["details"]
    # rewind raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.assess("sys", 1)


def test_full_compliance_kind_vocabulary():
    """All 8 pinned compliance kinds are accepted."""
    ledger = AICompliance()
    for i, kind in enumerate(COMPLIANCE_KINDS):
        rec = ledger.assess(f"sys-kind-{i}", i + 1, compliance_kind=kind)
        assert rec.compliance_kind == kind
        assert rec.verify()


def test_full_verdict_vocabulary():
    """All 5 pinned verdicts are accepted."""
    ledger = AICompliance()
    for i, verdict in enumerate(ASSESSMENT_VERDICTS):
        rec = ledger.assess(f"sys-verdict-{i}", i + 1, verdict=verdict)
        assert rec.verdict == verdict
        assert rec.verify()


def test_verify_semantics():
    """verify() is a pure read: tamper reported as data, seq not consumed."""
    ledger = AICompliance()
    rec = ledger.assess("sys-1", 1, verdict="compliant")
    rep = ledger.verify(rec.assessment_id, 5)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # pure read: seq shape-validated only, never consumed, no audit row
    n_rows = len(ledger.audit_log(6))
    ledger.verify(rec.assessment_id, 5)  # same seq again, no consumption
    ledger.verify(rec.assessment_id, 7)
    assert len(ledger.audit_log(8)) == n_rows
    # unknown ids refuse
    with pytest.raises(UnknownAssessmentError):
        ledger.verify("asm-999", 9)
    with pytest.raises(UnknownAssessmentError):
        ledger.verify("", 9)
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.assessment_id, "x")
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.assessment_id, True)


def test_verify_tamper_as_data():
    """Tampering flips integrity_ok as data; never raises."""
    ledger = AICompliance()
    rec = ledger.assess("sys-1", 1, verdict="compliant")
    tampered = ai_compliance.AssessmentRecord(
        assessment_id=rec.assessment_id,
        system_id=rec.system_id,
        seq=rec.seq,
        compliance_kind=rec.compliance_kind,
        verdict="non-compliant",  # changed after booking
        severity=rec.severity,
        assessment_digest=rec.assessment_digest,
        digest=rec.digest,
    )
    assert not tampered.verify()
    ledger._assessments[rec.assessment_id] = tampered
    rep = ledger.verify(rec.assessment_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    # evaluate flips integrity_ok as data too
    ev = ledger.evaluate("sys-1", 3)
    assert ev.integrity_ok is False


def test_evaluate_posture_math():
    """Ledger-rule posture precedence over verdict tallies."""
    ledger = AICompliance()
    # unassessed: all not-assessed
    ledger.assess("u", 1)
    ledger.assess("u", 2)
    ev = ledger.evaluate("u", 3)
    assert ev.posture == "unassessed"
    assert ev.n_assessments == 2 and ev.n_not_assessed == 2
    # compliant: all compliant
    ledger.assess("c", 4, verdict="compliant")
    ledger.assess("c", 5, verdict="compliant")
    ev = ledger.evaluate("c", 6)
    assert ev.posture == "compliant"
    assert ev.n_compliant == 2
    # partially-compliant: any partial, none worse
    ledger.assess("p", 7, verdict="compliant")
    ledger.assess("p", 8, verdict="partially-compliant")
    ev = ledger.evaluate("p", 9)
    assert ev.posture == "partially-compliant"
    assert ev.n_partial == 1
    # contested: inconclusive outranks partial
    ledger.assess("i", 10, verdict="partially-compliant")
    ledger.assess("i", 11, verdict="inconclusive")
    ev = ledger.evaluate("i", 12)
    assert ev.posture == "contested"
    assert ev.n_inconclusive == 1
    # non-compliant outranks everything
    ledger.assess("n", 13, verdict="non-compliant")
    ledger.assess("n", 14, verdict="compliant")
    ledger.assess("n", 15, verdict="inconclusive")
    ev = ledger.evaluate("n", 16)
    assert ev.posture == "non-compliant"
    assert ev.n_noncompliant == 1
    assert ev.integrity_ok is True
    assert ev.verify()
    # pure read: same seq twice, no audit rows added
    n_rows = len(ledger.audit_log(17))
    ledger.evaluate("n", 16)
    assert len(ledger.audit_log(18)) == n_rows
    # unknown system refuses
    with pytest.raises(UnknownSystemError):
        ledger.evaluate("ghost", 19)
    # bad seq shape refuses
    with pytest.raises(SeqOrderError):
        ledger.evaluate("n", "x")


def test_retire_terminality():
    """retire() is terminal; ids are never recycled; reads still work."""
    ledger = AICompliance()
    rec = ledger.assess("sys-1", 1, verdict="compliant")
    # unknown system refuses
    with pytest.raises(UnknownSystemError):
        ledger.retire("ghost", 2)
    # bad reason refuses
    with pytest.raises(BadReasonError):
        ledger.retire("sys-1", 3, reason="nope")
    ret = ledger.retire("sys-1", 4, reason="decommissioned")
    assert ret.verify()
    assert ret.reason == "decommissioned"
    assert ledger.retired_ids(5) == ("sys-1",)
    # all retire reasons accepted on fresh systems
    for i, reason in enumerate(RETIRE_REASONS):
        ledger.assess(f"sys-r{i}", 6 + i * 2)
        r = ledger.retire(f"sys-r{i}", 7 + i * 2, reason=reason)
        assert r.reason == reason
    # double-retire refuses
    with pytest.raises(RetiredSystemError):
        ledger.retire("sys-1", 14)
    # post-retire mutations refuse; ids never recycled
    with pytest.raises(RetiredSystemError):
        ledger.assess("sys-1", 15, verdict="compliant")
    # post-retire reads still work
    rep = ledger.verify(rec.assessment_id, 16)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 17)
    assert ev.posture == "compliant"
    assert ledger.assessment_record(rec.assessment_id, 18) is rec
    assert ledger.retire_record("sys-1", 19) is ret


def test_seq_discipline():
    """Genesis rewind raises bare with zero rows; malformed seqs refuse."""
    ledger = AICompliance()
    with pytest.raises(SeqOrderError):
        ledger.assess("sys", 0)
    assert len(ledger.audit_log(1)) == 0
    ledger.assess("sys", 1)
    with pytest.raises(SeqOrderError):
        ledger.assess("sys", 1)  # rewind raises bare, burns nothing
    with pytest.raises(SeqOrderError):
        ledger.retire("sys", 1)
    for bad in (True, "2", 2.0, None):
        with pytest.raises(SeqOrderError):
            ledger.assess("sys", bad)
    # failed mutation consumes seq
    with pytest.raises(BadVerdictError):
        ledger.assess("sys", 2, verdict="bogus")
    ledger.assess("sys", 3)  # seq 2 was burned
    assert ledger.stats(4)["seq"] == 3


def test_audit_shapes_and_leak_ban():
    """Audit rows have the house schema; banned keys and kinds raise."""
    row = ai_compliance_audit_event("assessed", 1, assessment_id="asm-1")
    assert row == {
        "schema": "audit.ndjson/1",
        "module": "ai-compliance",
        "version": AI_COMPLIANCE_VERSION,
        "kind": "assessed",
        "seq": 1,
        "details": {"assessment_id": "asm-1"},
    }
    # banned raw-material keys raise
    for banned in ("audit_evidence", "compliance_report", "remediation_plan",
                  "policy_text", "regulation_text", "legal_advice",
                  "findings_report", "control_evidence", "assessor_notes",
                  "gap_analysis", "corrective_action", "weights",
                  "password", "api_key", "pii", "payload"):
        with pytest.raises(AIComplianceError):
            ai_compliance_audit_event("assessed", 2, **{banned: "raw"})
    # pinned vocab values and digest pins remain emittable as declared data
    row = ai_compliance_audit_event(
        "assessed", 3, compliance_kind="data-governance",
        verdict="compliant", assessment_digest=GOOD_DIGEST,
    )
    assert row["details"]["compliance_kind"] == "data-governance"
    # bad kind raises
    with pytest.raises(AuditKindError):
        ai_compliance_audit_event("bogus", 4)
    # bad seq raises
    with pytest.raises(SeqOrderError):
        ai_compliance_audit_event("assessed", "x")
    # the assess() audit row carries pinned data but no raw material
    ledger = AICompliance()
    ledger.assess("sys", 1, compliance_kind="safety-standards",
                 verdict="partially-compliant", assessment_digest=GOOD_DIGEST)
    rows = ledger.audit_log(2)
    assert rows[0]["kind"] == "assessed"
    details = rows[0]["details"]
    assert details["compliance_kind"] == "safety-standards"
    assert details["verdict"] == "partially-compliant"
    assert details["assessment_digest"] == GOOD_DIGEST


def test_views_and_stats():
    """Pure-read views expose ledger state without consuming seqs."""
    ledger = AICompliance()
    rec1 = ledger.assess("b", 1, verdict="compliant")
    rec2 = ledger.assess("a", 2, verdict="non-compliant")
    rec3 = ledger.assess("a", 3, verdict="inconclusive")
    assert ledger.assessment_record(rec1.assessment_id, 4) is rec1
    with pytest.raises(UnknownAssessmentError):
        ledger.assessment_record("asm-999", 5)
    assert ledger.assessments_for("a", 6) == (rec2, rec3)
    assert ledger.assessments_for("ghost", 7) == ()
    assert ledger.system_ids(8) == ("a", "b")
    assert ledger.assessment_ids(9) == ("asm-1", "asm-2", "asm-3")
    assert ledger.retired_ids(10) == ()
    stats = ledger.stats(11)
    assert stats["n_systems"] == 2
    assert stats["n_assessments"] == 3
    assert stats["n_retired"] == 0
    assert stats["seq"] == 3
    assert stats["version"] == AI_COMPLIANCE_VERSION
    # retire reflects in views
    ledger.retire("a", 12)
    assert ledger.retired_ids(13) == ("a",)
    assert ledger.stats(14)["n_retired"] == 1
    with pytest.raises(UnknownSystemError):
        ledger.retire_record("b", 15)
    assert ledger.retire_record("a", 16).system_id == "a"


def test_cross_instance_and_threads():
    """Digest pins are deterministic across instances; reads are thread-safe."""
    a, b = AICompliance(), AICompliance()
    ra = a.assess("sys", 1, compliance_kind="data-governance",
                  verdict="compliant", severity=5, assessment_digest=GOOD_DIGEST)
    rb = b.assess("sys", 1, compliance_kind="data-governance",
                  verdict="compliant", severity=5, assessment_digest=GOOD_DIGEST)
    assert ra.digest == rb.digest
    # tamper in one instance breaks its own verify() only
    tampered = ai_compliance.AssessmentRecord(
        assessment_id=rb.assessment_id, system_id=rb.system_id, seq=rb.seq,
        compliance_kind=rb.compliance_kind, verdict="non-compliant",
        severity=rb.severity, assessment_digest=rb.assessment_digest,
        digest=rb.digest,
    )
    b._assessments[rb.assessment_id] = tampered
    assert a.verify(ra.assessment_id, 2).verdict == "verified"
    assert b.verify(rb.assessment_id, 2).verdict == "tampered"
    # 8-thread read smoke
    ledger = AICompliance()
    ledger.assess("sys", 1, verdict="compliant")
    errors = []

    def reader(_):
        try:
            for _ in range(50):
                ledger.verify("asm-1", 1)
                ledger.evaluate("sys", 1)
                ledger.stats(1)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # records are frozen
    with pytest.raises(AttributeError):
        ra.severity = 99


def test_main_subprocess():
    """Module main() self-check runs green via subprocess."""
    proc = subprocess.run(
        [sys.executable, "-m", "ai_compliance"],
        cwd=str(Path(ai_compliance.__file__).parent),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-compliance OK: assess, verify, evaluate, retire, pins, audit" in proc.stdout
