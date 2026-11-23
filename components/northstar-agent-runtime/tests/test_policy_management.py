"""Tests for policy_management.py: draft / approve / review bookkeeping."""

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import policy_management as pm

HERE = Path(__file__).resolve().parent
MODULE = Path(__file__).resolve().parent.parent / "policy_management.py"


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def drafted(ledger=None, policy_id="POL-001", seq=1):
    ledger = ledger or pm.PolicyManagement()
    ledger.draft(policy_id, seq, policy_class="ai-governance",
                 body_digest=digest("body"))
    return ledger


def test_version_and_schema_pins():
    assert pm.POLICY_MANAGEMENT_VERSION == "policy-management.v1"
    assert pm.POLICY_MANAGEMENT_SCHEMA == "northstar.policy-management.v1"


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


def test_draft_roundtrip_and_verify():
    ledger = drafted()
    record = ledger.draft_record("POL-001", 2)
    assert record.policy_id == "POL-001"
    assert record.policy_class == "ai-governance"
    assert record.version == 1
    assert record.verify()
    assert ledger.policy_ids(3) == ("POL-001",)
    status = ledger.status("POL-001", 4)
    assert status.state == "drafted" and status.version == 1
    assert status.approvals == 0 and status.reviews == 0


def test_draft_refusals_consume_seq():
    ledger = drafted()
    ledger.approve("POL-001", "ai-governance-board", 2)
    with pytest.raises(pm.PolicyStateError):
        ledger.draft("POL-001", 3, policy_class="security")
    rejected = [e for e in ledger.audit_log(4)
                if e["kind"] == pm.KIND_REJECTED]
    assert len(rejected) == 1
    for bad_seq in (True, "x", -1):
        with pytest.raises(pm.SeqOrderError):
            ledger.draft("BAD", bad_seq)
    seq = 4
    for bad_id in ("", "  ", "has space", None, 123):
        with pytest.raises(pm.BadPolicyError):
            ledger.draft(bad_id, seq)
        seq += 1
    for bad_class in ("", "legal", None, 42):
        with pytest.raises(pm.BadClassError):
            ledger.draft("NEW-1", seq, policy_class=bad_class)
        seq += 1
    with pytest.raises(pm.BadDigestError):
        ledger.draft("NEW-2", seq, body_digest="not-a-pin")
    assert ledger.stats(seq + 1)["policies"] == 1


def test_redraft_bumps_version():
    ledger = drafted()
    ledger.approve("POL-001", "ai-governance-board", 2)
    ledger.review("POL-001", 3, outcome="revise")
    v2 = ledger.draft("POL-001", 4, policy_class="ai-governance",
                      body_digest=digest("body-v2"))
    assert v2.version == 2 and v2.verify()
    history = ledger.draft_history("POL-001", 5)
    assert [r.version for r in history] == [1, 2]
    assert ledger.draft_record("POL-001", 6).version == 2


def test_approve_roundtrip_and_verify():
    ledger = drafted()
    record = ledger.approve("POL-001", "ai-governance-board", 2,
                            approval_digest=digest("sig"))
    assert record.policy_id == "POL-001"
    assert record.version == 1
    assert record.approver == "ai-governance-board"
    assert record.verify()
    status = ledger.status("POL-001", 3)
    assert status.state == "approved" and status.approvals == 1
    history = ledger.approval_history("POL-001", 4)
    assert len(history) == 1 and history[0].verify()


def test_approve_refusals():
    ledger = drafted()
    with pytest.raises(pm.UnknownPolicyError):
        ledger.approve("NOPE", "ciso", 2)
    with pytest.raises(pm.BadDigestError):
        ledger.approve("POL-001", "ciso", 3, approval_digest="raw-text")
    seq = 4
    for bad_approver in ("", "  ", "has space", None, 42):
        with pytest.raises(pm.BadApproverError):
            ledger.approve("POL-001", bad_approver, seq)
        seq += 1
    ledger.approve("POL-001", "ciso", seq)
    with pytest.raises(pm.PolicyStateError):
        ledger.approve("POL-001", "ciso", seq + 1)
    rejected = [e for e in ledger.audit_log(seq + 2)
                if e["kind"] == pm.KIND_REJECTED]
    assert len(rejected) == 8


def test_review_roundtrip_outcomes():
    ledger = drafted()
    ledger.approve("POL-001", "ai-governance-board", 2)
    r1 = ledger.review("POL-001", 3, outcome="reaffirm",
                       review_digest=digest("notes"))
    assert r1.review_id == "rev-1" and r1.verify()
    assert ledger.status("POL-001", 4).state == "approved"
    r2 = ledger.review("POL-001", 5, outcome="revise")
    assert r2.review_id == "rev-2" and r2.verify()
    assert ledger.status("POL-001", 6).state == "drafted"
    assert ledger.status("POL-001", 6).latest_review_outcome == "revise"
    history = ledger.review_history("POL-001", 7)
    assert [r.outcome for r in history] == ["reaffirm", "revise"]


def test_review_refusals():
    ledger = drafted()
    with pytest.raises(pm.UnknownPolicyError):
        ledger.review("NOPE", 2)
    with pytest.raises(pm.PolicyStateError):
        ledger.review("POL-001", 3)
    ledger.approve("POL-001", "ciso", 4)
    with pytest.raises(pm.BadOutcomeError):
        ledger.review("POL-001", 5, outcome="retire")
    with pytest.raises(pm.BadDigestError):
        ledger.review("POL-001", 6, review_digest="not-a-pin")
    ledger.review("POL-001", 7, outcome="revise")
    with pytest.raises(pm.PolicyStateError):
        ledger.review("POL-001", 8)
    rejected = [e for e in ledger.audit_log(9)
                if e["kind"] == pm.KIND_REJECTED]
    assert len(rejected) == 5


def test_full_lifecycle():
    ledger = pm.PolicyManagement()
    ledger.draft("POL-7", 1, policy_class="privacy", body_digest=digest("v1"))
    ledger.approve("POL-7", "privacy-officer", 2)
    ledger.review("POL-7", 3, outcome="revise")
    ledger.draft("POL-7", 4, policy_class="privacy", body_digest=digest("v2"))
    ledger.approve("POL-7", "privacy-officer", 5)
    ledger.review("POL-7", 6, outcome="reaffirm")
    status = ledger.status("POL-7", 7)
    assert status.state == "approved" and status.version == 2
    assert status.approvals == 2 and status.reviews == 2
    assert status.latest_review_outcome == "reaffirm"
    assert ledger.approval_history("POL-7", 8)[1].verify()
    assert ledger.stats(9)["policies"] == 1


def test_seq_discipline():
    ledger = drafted()
    with pytest.raises(pm.SeqOrderError):
        ledger.draft("P2", 1)
    rejected = [e for e in ledger.audit_log(2)
                if e["kind"] == pm.KIND_REJECTED]
    assert len(rejected) == 0
    for bad_seq in (True, "x", -1):
        with pytest.raises(pm.SeqOrderError):
            ledger.draft("P2", bad_seq)
    with pytest.raises(pm.BadClassError):
        ledger.draft("P2", 2, policy_class="nope")
    ledger.draft("P2", 3, policy_class="security")
    assert ledger.policy_ids(4) == ("P2", "POL-001")


def test_view_read_purity():
    ledger = drafted()
    ledger.approve("POL-001", "ciso", 2)
    before = len(ledger.audit_log(3))
    for _ in range(2):
        ledger.draft_record("POL-001", 3)
        ledger.draft_history("POL-001", 3)
        ledger.approval_history("POL-001", 3)
        ledger.review_history("POL-001", 3)
        ledger.status("POL-001", 3)
        ledger.policy_ids(3)
        ledger.stats(3)
        ledger.audit_log(3)
    assert len(ledger.audit_log(4)) == before
    with pytest.raises(pm.UnknownPolicyError):
        ledger.draft_record("NOPE", 5)
    with pytest.raises(pm.UnknownPolicyError):
        ledger.status("NOPE", 6)


def test_audit_shapes_and_leak_ban():
    ledger = drafted()
    ledger.approve("POL-001", "ciso", 2)
    ledger.review("POL-001", 3, outcome="reaffirm")
    kinds = [e["kind"] for e in ledger.audit_log(4)]
    assert pm.KIND_DRAFTED in kinds
    assert pm.KIND_APPROVED in kinds
    assert pm.KIND_REVIEWED in kinds
    for event in ledger.audit_log(5):
        assert event["schema"] == "audit.ndjson/1"
        for key in event["detail"]:
            assert key not in pm._BANNED_AUDIT_KEYS, key
    with pytest.raises(pm.AuditKindError):
        pm.policy_management_audit_event("bogus-kind", 1)
    with pytest.raises(pm.AuditKindError):
        pm.policy_management_audit_event(
            pm.KIND_DRAFTED, 1, body="raw text")
    ok = pm.policy_management_audit_event(
        pm.KIND_DRAFTED, 1, policy_id="P", body_digest=digest("x"))
    assert ok["detail"]["policy_id"] == "P"


def test_cross_instance_determinism_and_tamper():
    def build():
        ledger = pm.PolicyManagement()
        ledger.draft("POL-1", 1, policy_class="security",
                     body_digest=digest("b"))
        ledger.approve("POL-1", "ciso", 2, approval_digest=digest("s"))
        return ledger

    a, b = build(), build()
    assert a.draft_record("POL-1", 3).digest == b.draft_record("POL-1", 3).digest
    assert a.approval_history("POL-1", 3)[0].digest == \
        b.approval_history("POL-1", 3)[0].digest
    record = a.draft_record("POL-1", 4)
    with pytest.raises(Exception):
        record.policy_id = "X"  # type: ignore[misc]
    bad = pm.DraftRecord(
        policy_id=record.policy_id,
        policy_class="privacy",
        version=record.version,
        body_digest=record.body_digest,
        seq=record.seq,
        digest=record.digest,
    )
    assert not bad.verify()


def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "policy-management OK" in result.stdout
