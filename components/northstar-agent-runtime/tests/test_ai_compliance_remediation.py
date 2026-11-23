"""Tests for the ai-compliance-remediation decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_compliance_remediation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_compliance_remediation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_compliance_remediation"] = module
    spec.loader.exec_module(module)
    return module


acr = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert acr.AI_COMPLIANCE_REMEDIATION_VERSION == "ai-compliance-remediation.v1"
    assert acr.SCHEMA_PIN == "northstar.ai-compliance-remediation.v1"
    assert acr.COMPLIANCE_REMEDIATION_KINDS == (
        "compliance-policy-repair",
        "control-restoration",
        "evidence-retention-restoration",
        "audit-trail-completion",
        "governance-control-remediation",
        "monitoring-calibration",
        "regulatory-filing-remediation",
        "no-action",
    )
    assert acr.REMEDIATION_OUTCOMES == (
        "remediated",
        "partial",
        "failed",
        "inconclusive",
    )
    assert acr.VERIFY_VERDICTS == ("verified", "tampered")
    assert acr.POSTURES == (
        "unevaluated",
        "contested",
        "partially-remediated",
        "failed",
        "remediated",
    )
    assert acr.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert acr.AUDIT_KINDS == ("remediated", "retired", "rejected")


# 2. stdlib-only AST self-check (module's own + independent scan)
def test_stdlib_only_ast():
    assert acr.stdlib_only() is True
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
    tree = ast.parse(MOD.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. remediate roundtrip / crm-N minting / verify() / frozen-ness / defaults
def test_remediate_roundtrip_minting_verify_frozenness():
    ledger = acr.AIComplianceRemediation()
    rec = ledger.remediate("issue-1", 1)
    assert rec.remediation_id == "crm-1"
    assert rec.issue_id == "issue-1"
    assert rec.seq == 1
    assert rec.compliance_remediation_kind == "no-action"
    assert rec.outcome == "inconclusive"
    assert rec.compliance_digest == ""
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    rec2 = ledger.remediate(
        "issue-1",
        2,
        compliance_remediation_kind="compliance-policy-repair",
        outcome="remediated",
        compliance_digest=PIN,
    )
    assert rec2.remediation_id == "crm-2"
    assert rec2.compliance_digest == PIN
    assert rec2.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "failed"  # type: ignore[misc]
    # minted ids are ledger-local and strictly increasing
    rec3 = ledger.remediate("issue-2", 3)
    assert rec3.remediation_id == "crm-3"


# 4. bad-input table + seq-burn + rejected-row accounting
def test_bad_input_table_seq_burn_rejected_rows():
    ledger = acr.AIComplianceRemediation()
    bad_cases = [
        # (kwargs, expected error class)
        ({"issue_id": ""}, "BadIssueError"),
        ({"issue_id": None}, "BadIssueError"),
        ({"issue_id": 123}, "BadIssueError"),
        ({"issue_id": True}, "BadIssueError"),
        ({"issue_id": "i", "compliance_remediation_kind": "bogus"}, "BadKindError"),
        ({"issue_id": "i", "outcome": "bogus"}, "BadOutcomeError"),
        ({"issue_id": "i", "compliance_digest": "sha256:xyz"}, "BadDigestError"),
        ({"issue_id": "i", "compliance_digest": "nope"}, "BadDigestError"),
        ({"issue_id": "i", "compliance_digest": "sha256:" + "zz" * 32}, "BadDigestError"),
    ]
    seq = 0
    for kwargs, err_name in bad_cases:
        seq += 1
        with pytest.raises(getattr(acr, err_name)):
            ledger.remediate(seq=seq, **kwargs)
        row = ledger.audit_log(0)[-1]
        assert row["kind"] == "rejected"
        assert row["details"]["rejected_kind"] == err_name
        # burned seq: reuse must raise bare SeqOrderError
        with pytest.raises(acr.SeqOrderError):
            ledger.remediate(issue_id="i", seq=seq)
    # valid seq after the burned ones still works
    seq += 1
    rec = ledger.remediate("i", seq)
    assert rec.verify() is True


# 5. rewinds raise bare (no burn, no audit row)
def test_seq_rewind_raises_bare():
    ledger = acr.AIComplianceRemediation()
    ledger.remediate("issue-1", 5)
    n_rows = len(ledger.audit_log(0))
    with pytest.raises(acr.SeqOrderError):
        ledger.remediate("issue-1", 5)
    with pytest.raises(acr.SeqOrderError):
        ledger.remediate("issue-1", 1)
    assert len(ledger.audit_log(0)) == n_rows
    assert ledger.stats(0)["seq"] == 5


# 6. full 8-kind compliance-remediation vocabulary
def test_full_kind_vocabulary():
    ledger = acr.AIComplianceRemediation()
    for i, kind in enumerate(acr.COMPLIANCE_REMEDIATION_KINDS):
        rec = ledger.remediate(
            f"issue-kind-{i}", i + 1, compliance_remediation_kind=kind
        )
        assert rec.compliance_remediation_kind == kind
        assert rec.verify() is True


# 7. full 4-outcome vocabulary + tallies + failed-outranks
def test_full_outcome_vocabulary_tallies_and_failed_outranks():
    ledger = acr.AIComplianceRemediation()
    ledger.remediate("issue-a", 1, outcome="remediated")
    ledger.remediate("issue-a", 2, outcome="partial")
    ledger.remediate("issue-a", 3, outcome="inconclusive")
    ev = ledger.evaluate("issue-a", 4)
    assert ev.n_remediations == 3
    assert ev.n_remediated == 1
    assert ev.n_partial == 1
    assert ev.n_inconclusive == 1
    assert ev.n_failed == 0
    assert ev.posture == "contested"
    ledger.remediate("issue-a", 5, outcome="failed")
    ev2 = ledger.evaluate("issue-a", 6)
    assert ev2.posture == "failed"
    assert ev2.n_failed == 1


# 8. verify semantics: tamper-as-data, read purity, unknown refusal
def test_verify_semantics_tamper_as_data_and_read_purity():
    ledger = acr.AIComplianceRemediation()
    rec = ledger.remediate("issue-1", 1, outcome="remediated")
    rep = ledger.verify(rec.remediation_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    n_rows = len(ledger.audit_log(0))
    seq_before = ledger.stats(0)["seq"]
    # pure read: same seq twice, no rows, seq unconsumed
    rep2 = ledger.verify(rec.remediation_id, 2)
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(0)) == n_rows
    assert ledger.stats(0)["seq"] == seq_before
    # tamper: outcome flipped out-of-band -> reported as data, never raised
    tampered = dataclasses.replace(rec, outcome="failed")
    ledger._remediations[rec.remediation_id] = tampered
    assert tampered.verify() is False
    rep3 = ledger.verify(rec.remediation_id, 3)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    with pytest.raises(acr.UnknownRecordError):
        ledger.verify("crm-999", 4)


# 9. evaluate posture math: all reachable postures + precedence
def test_evaluate_posture_math():
    ledger = acr.AIComplianceRemediation()
    # all remediated -> remediated
    ledger.remediate("p1", 1, outcome="remediated")
    assert ledger.evaluate("p1", 2).posture == "remediated"
    # partial only -> partially-remediated
    ledger.remediate("p2", 3, outcome="partial")
    assert ledger.evaluate("p2", 4).posture == "partially-remediated"
    # inconclusive (no failed) -> contested
    ledger.remediate("p3", 5, outcome="inconclusive")
    assert ledger.evaluate("p3", 6).posture == "contested"
    # failed outranks partial and inconclusive
    ledger.remediate("p4", 7, outcome="partial")
    ledger.remediate("p4", 8, outcome="inconclusive")
    ledger.remediate("p4", 9, outcome="failed")
    assert ledger.evaluate("p4", 10).posture == "failed"
    # unknown issue refuses
    with pytest.raises(acr.UnknownIssueError):
        ledger.evaluate("nope", 11)


# 10. evaluate purity + tamper flips integrity_ok
def test_evaluate_purity_and_integrity_flip():
    ledger = acr.AIComplianceRemediation()
    rec = ledger.remediate("issue-1", 1, outcome="remediated")
    ev = ledger.evaluate("issue-1", 2)
    assert ev.posture == "remediated"
    assert ev.integrity_ok is True
    assert ev.verify() is True
    n_rows = len(ledger.audit_log(0))
    ev2 = ledger.evaluate("issue-1", 2)
    assert ev2.digest == ev.digest
    assert len(ledger.audit_log(0)) == n_rows
    # tamper a non-outcome field: posture stays, integrity flips
    tampered = dataclasses.replace(
        rec, compliance_remediation_kind="control-restoration"
    )
    ledger._remediations[rec.remediation_id] = tampered
    ev3 = ledger.evaluate("issue-1", 3)
    assert ev3.posture == "remediated"
    assert ev3.integrity_ok is False


# 11. retire terminality + all 4 reasons + bad reason + post-retire reads
def test_retire_terminality_reasons_and_reads():
    ledger = acr.AIComplianceRemediation()
    ledger.remediate("issue-1", 1, outcome="remediated")
    with pytest.raises(acr.BadReasonError):
        ledger.retire("issue-1", 2, reason="bogus")
    # all four reasons accepted on distinct issues
    reasons = list(acr.RETIRE_REASONS)
    for i, reason in enumerate(reasons):
        iid = f"issue-r{i}"
        ledger.remediate(iid, 3 + i * 4, outcome="remediated")
        ret = ledger.retire(iid, 4 + i * 4, reason=reason)
        assert ret.reason == reason
        assert ret.verify() is True
        # double retire refused
        with pytest.raises(acr.RetiredIssueError):
            ledger.retire(iid, 5 + i * 4)
        # post-retire mutation refused, ids never recycled
        with pytest.raises(acr.RetiredIssueError):
            ledger.remediate(iid, 6 + i * 4)
        # post-retire reads still work
        ev = ledger.evaluate(iid, 7 + i * 4)
        assert ev.posture == "remediated"
    # unknown issue retire refused (burns seq)
    with pytest.raises(acr.UnknownIssueError):
        ledger.retire("ghost", 100)
    assert ledger.audit_log(0)[-1]["details"]["rejected_kind"] == "UnknownIssueError"


# 12. seq discipline: malformed seqs, gap seqs, reads shape-validated
def test_seq_discipline():
    ledger = acr.AIComplianceRemediation()
    for bad_seq in (True, "1", 1.5, -1, None):
        with pytest.raises(acr.SeqOrderError):
            ledger.remediate("issue-1", bad_seq)
    # gap seqs allowed
    rec = ledger.remediate("issue-1", 10)
    assert rec.seq == 10
    # reads only need shape-valid seqs
    assert ledger.stats(0)["seq"] == 10
    assert ledger.issue_ids(0) == ("issue-1",)
    with pytest.raises(acr.SeqOrderError):
        ledger.stats(-1)


# 13. audit shapes + leak ban + bad-kind + pinned-data passthrough
def test_audit_shapes_leak_ban_and_bad_kind():
    ledger = acr.AIComplianceRemediation()
    rec = ledger.remediate(
        "issue-1",
        1,
        compliance_remediation_kind="regulatory-filing-remediation",
        outcome="partial",
    )
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-compliance-remediation"
    assert row["version"] == "ai-compliance-remediation.v1"
    assert row["kind"] == "remediated"
    assert row["seq"] == 1
    assert row["details"]["compliance_remediation_kind"] == "regulatory-filing-remediation"
    assert row["details"]["outcome"] == "partial"
    assert row["details"]["remediation_id"] == rec.remediation_id
    ledger.retire("issue-1", 2)
    assert ledger.audit_log(0)[-1]["kind"] == "retired"
    # leak ban: raw compliance material may not cross the audit boundary
    for banned in (
        "compliance_report",
        "regulatory_filing",
        "legal_opinion",
        "fine_notice",
        "inspection_record",
        "violation_narrative",
        "control_attestation",
    ):
        with pytest.raises(acr.AIComplianceRemediationError):
            acr.ai_compliance_remediation_audit_event(
                "remediated", 3, **{banned: "raw-material"}
            )
    # digest pins of banned material are fine; pinned vocab values emittable
    ok = acr.ai_compliance_remediation_audit_event(
        "remediated",
        3,
        compliance_report_digest=PIN,
        compliance_remediation_kind="no-action",
    )
    assert ok["details"]["compliance_remediation_kind"] == "no-action"
    # bad kind fail-closed
    with pytest.raises(acr.AuditKindError):
        acr.ai_compliance_remediation_audit_event("bogus", 4)


# 14. views/stats + unknown lookups + cross-instance digest determinism
def test_views_stats_and_unknown_lookups():
    ledger = acr.AIComplianceRemediation()
    ledger.remediate("b-issue", 1, outcome="remediated")
    ledger.remediate("a-issue", 2, outcome="failed")
    rec = ledger.remediation_record("crm-1", 3)
    assert rec.issue_id == "b-issue"
    assert ledger.remediations_for("b-issue", 4) == (rec,)
    assert ledger.remediations_for("ghost", 5) == ()
    assert ledger.issue_ids(6) == ("a-issue", "b-issue")
    assert ledger.remediation_ids(7) == ("crm-1", "crm-2")
    assert ledger.retired_ids(8) == ()
    stats = ledger.stats(9)
    assert stats["n_issues"] == 2
    assert stats["n_remediations"] == 2
    assert stats["n_retired"] == 0
    assert stats["n_audit_rows"] == 2
    with pytest.raises(acr.UnknownRemediationError):
        ledger.remediation_record("crm-999", 10)
    with pytest.raises(acr.UnknownRecordError):
        ledger.verify("crm-999", 11)
    # determinism across instances
    other = acr.AIComplianceRemediation()
    other.remediate("b-issue", 1, outcome="remediated")
    assert other.remediation_record("crm-1", 2).digest == rec.digest


# 15. 8-thread read smoke + main() subprocess check
def test_concurrency_and_main():
    ledger = acr.AIComplianceRemediation()
    rec = ledger.remediate("issue-1", 1, outcome="remediated")
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.verify(rec.remediation_id, 2)
                ledger.evaluate("issue-1", 3)
                ledger.stats(4)
                ledger.issue_ids(5)
                ledger.audit_log(6)
        except Exception as exc:  # pragma: no cover - smoke only
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert (
        "ai-compliance-remediation OK: remediate, verify, evaluate, retire, pins, audit"
        in proc.stdout
    )
