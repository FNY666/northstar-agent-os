"""Tests for audit_agents (one-hundred-forty-third batch)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519
from canonical_json import jcs_canonical_json

from audit_agents import (
    AuditError,
    AuditVerdict,
    AuthorityRegistry,
    ReconstructionReceipt,
    ReconstructionRegistry,
    ParallelRunReceipt,
    ParallelRunRegistry,
    InventoryEntry,
    InventoryRegistry,
    CharterReceipt,
    CharterRegistry,
    IncidentProcedureReceipt,
    IncidentProcedureRegistry,
    reconstruction_receipt,
    parallel_run_gate,
    evidence_not_conclusion,
    shadow_ai_inventory,
    decision_rights_charter,
    oversight_capacity_ratio,
    incident_procedure_gate,
    alert_conversion_probe,
    continuous_ready_gate,
    CLASS_AUTHORITATIVE,
    CLASS_NON_AUTHORITATIVE,
)


SEC = b"\x0a" * 32
PUB = ed25519.public_key(SEC).hex()
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
HEX64_C = "ef" * 32


def _authorities():
    reg = AuthorityRegistry()
    reg.register("bench-op", PUB)
    return reg


def _signed_placeholder(payload):
    """Sign a payload built with the placeholder signature."""
    return ed25519.sign(SEC, jcs_canonical_json(payload))


class TestFieldChecks(unittest.TestCase):
    def test_bad_hex64_raises(self):
        with self.assertRaises(AuditError):
            ReconstructionRegistry(_authorities()).issue(
                "r", "w", "nope", HEX64, HEX64, "v1", "rev",
                T0, "bench-op", b"x" * 64, T0)

    def test_unknown_authority_raises(self):
        reg = ReconstructionRegistry(AuthorityRegistry())
        with self.assertRaises(AuditError):
            reg.issue("r", "w", HEX64, HEX64, HEX64, "v1", "rev",
                      T0, "ghost-op", b"x" * 64, T0)

    def test_verdict_shapes(self):
        v = reconstruction_receipt(ReconstructionRegistry(_authorities()), "w", T0)
        self.assertIsInstance(v, AuditVerdict)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)


def _issue_recon(reg, receipt_id, work_id, reviewed_at=T0):
    r = ReconstructionReceipt(
        receipt_id=receipt_id, work_id=work_id,
        prompt_digest=HEX64, input_digest=HEX64_B, output_digest=HEX64_C,
        model_version="model-7", human_reviewer_id="rev-chen",
        reviewed_at=reviewed_at, authority_id="bench-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        prev_digest=reg.log[-1].receipt_digest if reg.log else "genesis")
    sig = _signed_placeholder(r._payload())
    return reg.issue(
        receipt_id=receipt_id, work_id=work_id,
        prompt_digest=HEX64, input_digest=HEX64_B, output_digest=HEX64_C,
        model_version="model-7", human_reviewer_id="rev-chen",
        reviewed_at=reviewed_at, authority_id="bench-op",
        signature=sig, issued_now=T0)


class TestReconstruction(unittest.TestCase):
    def setUp(self):
        self.reg = ReconstructionRegistry(_authorities())

    def test_allow_fresh_receipt(self):
        _issue_recon(self.reg, "r-1", "work-1")
        v = reconstruction_receipt(self.reg, "work-1", T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_AUTHORITATIVE)

    def test_deny_no_receipt(self):
        v = reconstruction_receipt(self.reg, "work-ghost", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_reconstruction", v.reason)

    def test_deny_stale_review(self):
        _issue_recon(self.reg, "r-2", "work-2", reviewed_at=T0 - 91 * 86400)
        v = reconstruction_receipt(self.reg, "work-2", T0)
        self.assertFalse(v.allowed)
        self.assertIn("stale_reconstruction", v.reason)

    def test_deny_future_review(self):
        _issue_recon(self.reg, "r-3", "work-3", reviewed_at=T0 + 999)
        v = reconstruction_receipt(self.reg, "work-3", T0)
        self.assertFalse(v.allowed)
        self.assertIn("future_review", v.reason)

    def test_tamper_breaks_chain(self):
        _issue_recon(self.reg, "r-4", "work-4")
        self.reg.log[0] = ReconstructionReceipt(
            **{**self.reg.log[0].__dict__, "output_digest": HEX64})
        v = reconstruction_receipt(self.reg, "work-4", T0)
        self.assertFalse(v.allowed)
        self.assertIn("chain_broken", v.reason)


def _issue_parallel(reg, receipt_id, tool_id, cycles, recorded_at=T0):
    r = ParallelRunReceipt(
        receipt_id=receipt_id, tool_id=tool_id, cycles_run=cycles,
        human_audit_digest=HEX64, agreement_rate=0.97,
        authority_id="bench-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, recorded_at=recorded_at,
        prev_digest=reg.log[-1].receipt_digest if reg.log else "genesis")
    sig = _signed_placeholder(r._payload())
    return reg.issue(
        receipt_id=receipt_id, tool_id=tool_id, cycles_run=cycles,
        human_audit_digest=HEX64, agreement_rate=0.97,
        authority_id="bench-op", signature=sig, recorded_at=recorded_at)


class TestParallelRun(unittest.TestCase):
    def setUp(self):
        self.reg = ParallelRunRegistry(_authorities())

    def test_allow_two_cycles(self):
        _issue_parallel(self.reg, "p-1", "tool-a", 2)
        v = parallel_run_gate(self.reg, "tool-a", T0)
        self.assertTrue(v.allowed)

    def test_deny_no_cycles_recorded(self):
        v = parallel_run_gate(self.reg, "tool-ghost", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_parallel_run", v.reason)

    def test_deny_zero_cycles(self):
        _issue_parallel(self.reg, "p-2", "tool-b", 0)
        v = parallel_run_gate(self.reg, "tool-b", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_parallel_run", v.reason)


class TestEvidenceNotConclusion(unittest.TestCase):
    def test_evidence_role_allows(self):
        v = evidence_not_conclusion("out-1", "evidence", False)
        self.assertTrue(v.allowed)

    def test_conclusion_without_signoff_denies(self):
        v = evidence_not_conclusion("out-2", "final-conclusion", False)
        self.assertFalse(v.allowed)
        self.assertIn("unconcluded", v.reason)

    def test_human_signed_conclusion_allows(self):
        v = evidence_not_conclusion("out-3", "final-conclusion", True)
        self.assertTrue(v.allowed)


def _issue_inventory(reg, receipt_id, component_id, digest=HEX64):
    r = InventoryEntry(
        receipt_id=receipt_id, component_id=component_id,
        component_digest=digest, purpose="journal sampling",
        authority_id="bench-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, registered_at=T0,
        prev_digest=reg.log[-1].receipt_digest if reg.log else "genesis")
    sig = _signed_placeholder(r._payload())
    return reg.issue(
        receipt_id=receipt_id, component_id=component_id,
        component_digest=digest, purpose="journal sampling",
        authority_id="bench-op", signature=sig, registered_at=T0)


class TestShadowAi(unittest.TestCase):
    def setUp(self):
        self.reg = InventoryRegistry(_authorities())

    def test_allow_registered(self):
        _issue_inventory(self.reg, "i-1", "sampler-v2")
        v = shadow_ai_inventory(self.reg, "sampler-v2", HEX64, T0)
        self.assertTrue(v.allowed)

    def test_deny_unregistered(self):
        v = shadow_ai_inventory(self.reg, "ghost-model", HEX64, T0)
        self.assertFalse(v.allowed)
        self.assertIn("shadow_ai", v.reason)

    def test_deny_swapped_digest(self):
        _issue_inventory(self.reg, "i-2", "sampler-v3")
        v = shadow_ai_inventory(self.reg, "sampler-v3", HEX64_B, T0)
        self.assertFalse(v.allowed)
        self.assertIn("shadow_ai", v.reason)


def _issue_charter(reg, receipt_id, charter_id, bound_at=T0,
                   expires_at=T0 + 3600):
    r = CharterReceipt(
        receipt_id=receipt_id, charter_id=charter_id,
        decision_rights_digest=HEX64, ai_decision_scope="sampling",
        human_decision_scope="final opinion", authority_id="bench-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        bound_at=bound_at, expires_at=expires_at,
        prev_digest=reg.log[-1].receipt_digest if reg.log else "genesis")
    sig = _signed_placeholder(r._payload())
    return reg.issue(
        receipt_id=receipt_id, charter_id=charter_id,
        decision_rights_digest=HEX64, ai_decision_scope="sampling",
        human_decision_scope="final opinion", authority_id="bench-op",
        signature=sig, bound_at=bound_at, expires_at=expires_at)


class TestCharter(unittest.TestCase):
    def setUp(self):
        self.reg = CharterRegistry(_authorities())

    def test_no_decision_needs_no_charter(self):
        v = decision_rights_charter(self.reg, "c-ghost", False, T0)
        self.assertTrue(v.allowed)

    def test_allow_live_charter(self):
        _issue_charter(self.reg, "c-1", "charter-a")
        v = decision_rights_charter(self.reg, "charter-a", True, T0 + 5)
        self.assertTrue(v.allowed)

    def test_deny_no_charter(self):
        v = decision_rights_charter(self.reg, "charter-ghost", True, T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_charter", v.reason)

    def test_deny_expired_charter(self):
        _issue_charter(self.reg, "c-2", "charter-b",
                       bound_at=T0 - 7200, expires_at=T0 - 3600)
        v = decision_rights_charter(self.reg, "charter-b", True, T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_charter", v.reason)


class TestOversight(unittest.TestCase):
    def test_allow_healthy(self):
        v = oversight_capacity_ratio(5, 2000, 0.12)
        self.assertTrue(v.allowed)

    def test_deny_rubber_stamp(self):
        v = oversight_capacity_ratio(5, 2000, 0.0)
        self.assertFalse(v.allowed)
        self.assertIn("rubber_stamp", v.reason)

    def test_deny_under_capacity(self):
        v = oversight_capacity_ratio(1, 50000, 0.5)
        self.assertFalse(v.allowed)
        self.assertIn("under_capacity", v.reason)

    def test_no_decisions_allows(self):
        v = oversight_capacity_ratio(0, 0, 0.0)
        self.assertTrue(v.allowed)


def _issue_procedure(reg, receipt_id, deployment_id, autonomy="highly_autonomous"):
    r = IncidentProcedureReceipt(
        receipt_id=receipt_id, deployment_id=deployment_id,
        procedure_digest=HEX64, autonomy_level=autonomy,
        authority_id="bench-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, bound_at=T0,
        prev_digest=reg.log[-1].receipt_digest if reg.log else "genesis")
    sig = _signed_placeholder(r._payload())
    return reg.issue(
        receipt_id=receipt_id, deployment_id=deployment_id,
        procedure_digest=HEX64, autonomy_level=autonomy,
        authority_id="bench-op", signature=sig, bound_at=T0)


class TestIncidentProcedure(unittest.TestCase):
    def setUp(self):
        self.reg = IncidentProcedureRegistry(_authorities())

    def test_assisted_needs_no_procedure(self):
        v = incident_procedure_gate(self.reg, "dep-1", "assisted", T0)
        self.assertTrue(v.allowed)

    def test_allow_bound_procedure(self):
        _issue_procedure(self.reg, "ip-1", "dep-2")
        v = incident_procedure_gate(self.reg, "dep-2", "highly_autonomous", T0 + 5)
        self.assertTrue(v.allowed)

    def test_deny_missing_procedure(self):
        v = incident_procedure_gate(self.reg, "dep-ghost", "highly_autonomous", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_incident_procedure", v.reason)


class TestAlertConversion(unittest.TestCase):
    def test_allow_healthy_channel(self):
        v = alert_conversion_probe("ch-1", 100, 30)
        self.assertTrue(v.allowed)

    def test_deny_fatigued_channel(self):
        v = alert_conversion_probe("ch-2", 100, 3)
        self.assertFalse(v.allowed)
        self.assertIn("alert_fatigue", v.reason)

    def test_silent_channel_allows(self):
        v = alert_conversion_probe("ch-3", 0, 0)
        self.assertTrue(v.allowed)

    def test_converted_above_raised_raises(self):
        with self.assertRaises(AuditError):
            alert_conversion_probe("ch-4", 5, 6)


class TestContinuousReady(unittest.TestCase):
    def test_docs_current_allows(self):
        v = continuous_ready_gate("2.4.0", "docs-88", "2.4.0")
        self.assertTrue(v.allowed)

    def test_stale_docs_deny(self):
        v = continuous_ready_gate("2.4.0", "docs-88", "2.3.0")
        self.assertFalse(v.allowed)
        self.assertIn("docs_stale", v.reason)


if __name__ == "__main__":
    unittest.main()
