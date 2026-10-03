"""Tests for deployment_registry.py (one-hundred-tenth batch)."""

import sys
import unittest

sys.path.insert(0, ".")

from deployment_registry import (
    DEPLOYMENT_DENIED_EVENT,
    SHADOW_DETECTED_EVENT,
    DeploymentRegistry,
    DeploymentRegistryError,
    RegistrationReceipt,
    deployment_audit_event,
    shadow_audit_event,
    REGISTERED_DEPLOYMENT,
    UNVERIFIABLE_DEPLOYMENT,
)


AUTHORITY_SECRET = bytes(range(32))
OTHER_SECRET = bytes([9] * 32)
T0 = 1_700_000_000
MODEL = "ab" * 32
DATA_RECORD = "cd" * 32
FRIA = "ef" * 32

EXPLAIN = {
    "decision": "benefit eligibility screening",
    "grounds": "income below threshold per rule 4.2",
    "data_used": "declared income, household size",
    "appeal_path": "request human review within 30 days",
}


def make_registry():
    import ed25519
    pub = ed25519.public_key(AUTHORITY_SECRET).hex()
    return DeploymentRegistry({"reg-authority": pub})


def register(reg, **over):
    kw = dict(
        authority_secret=AUTHORITY_SECRET,
        authority_id="reg-authority",
        system_id="welfare-screener-1",
        model_digest=MODEL,
        risk_class="high",
        fria_digest=FRIA,
        data_record_digest=DATA_RECORD,
        retention_floor_days=180,
        expires_at=T0 + 1_000_000,
        explanation_fields=dict(EXPLAIN),
    )
    kw.update(over)
    return reg.register_system(**kw)


class TestDeploymentRegistry(unittest.TestCase):
    def test_valid_high_risk_registration(self):
        reg = make_registry()
        r = register(reg)
        ok, reason = reg.verify_registration(r, now=T0)
        self.assertTrue(ok, reason)
        self.assertEqual(r.risk_class, "high")

    def test_unacceptable_refused_at_registration(self):
        reg = make_registry()
        with self.assertRaises(DeploymentRegistryError):
            register(reg, risk_class="unacceptable")

    def test_high_risk_needs_fria(self):
        reg = make_registry()
        with self.assertRaises(DeploymentRegistryError):
            register(reg, fria_digest=None)

    def test_high_risk_needs_explanation_fields(self):
        reg = make_registry()
        bad = dict(EXPLAIN)
        del bad["appeal_path"]
        with self.assertRaises(DeploymentRegistryError):
            register(reg, explanation_fields=bad)

    def test_unknown_risk_class_rejected(self):
        reg = make_registry()
        with self.assertRaises(DeploymentRegistryError):
            register(reg, risk_class="extreme")

    def test_gate_allows_valid_deployment(self):
        reg = make_registry()
        r = register(reg)
        v = reg.gate_deployment(receipt=r, intended_use="high",
                               log_retention_days=180, now=T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, REGISTERED_DEPLOYMENT)

    def test_gate_no_receipt_denies(self):
        reg = make_registry()
        v = reg.gate_deployment(receipt=None, intended_use="minimal",
                               log_retention_days=180, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, UNVERIFIABLE_DEPLOYMENT)

    def test_gate_expired_denies(self):
        reg = make_registry()
        r = register(reg, expires_at=T0 + 10)
        v = reg.gate_deployment(receipt=r, intended_use="high",
                               log_retention_days=180, now=T0 + 11)
        self.assertFalse(v.allowed)
        self.assertIn("expired", v.reason)

    def test_gate_intended_use_exceeds_class_denies(self):
        reg = make_registry()
        r = register(reg, risk_class="limited", fria_digest=None,
                     explanation_fields={})
        v = reg.gate_deployment(receipt=r, intended_use="high",
                               log_retention_days=180, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("risk class", v.reason)

    def test_gate_retention_below_floor_denies(self):
        reg = make_registry()
        r = register(reg)
        v = reg.gate_deployment(receipt=r, intended_use="high",
                               log_retention_days=179, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("below floor", v.reason)

    def test_tampered_receipt_denies(self):
        reg = make_registry()
        r = register(reg)
        tampered = RegistrationReceipt(
            system_id=r.system_id, model_digest="ff" * 32,
            risk_class=r.risk_class, fria_digest=r.fria_digest,
            data_record_digest=r.data_record_digest,
            retention_floor_days=r.retention_floor_days,
            registered_by=r.registered_by,
            authority_sig_hex=r.authority_sig_hex,
            expires_at=r.expires_at,
            explanation_fields=dict(r.explanation_fields),
            prev_hash=r.prev_hash, seq=r.seq)
        v = reg.gate_deployment(receipt=tampered, intended_use="high",
                               log_retention_days=180, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("signature", v.reason)

    def test_unknown_authority_denies(self):
        reg = make_registry()
        other = DeploymentRegistry({"other": "00" * 32})
        with self.assertRaises(DeploymentRegistryError):
            register(other, authority_secret=OTHER_SECRET,
                     authority_id="other")

    def test_superseded_registration_is_rollback(self):
        reg = make_registry()
        r1 = register(reg)
        r2 = register(reg, model_digest="11" * 32)
        ok, reason = reg.verify_registration(r1, now=T0)
        self.assertFalse(ok)
        self.assertIn("rollback", reason)
        ok2, _ = reg.verify_registration(r2, now=T0)
        self.assertTrue(ok2)

    def test_chain_integrity(self):
        reg = make_registry()
        register(reg)
        register(reg, system_id="other-system", risk_class="minimal",
                 fria_digest=None, explanation_fields={})
        ok, reason = reg.verify_chain()
        self.assertTrue(ok, reason)

    def test_detect_shadow_unknown_system(self):
        reg = make_registry()
        register(reg)
        v = reg.detect_shadow(system_id="ghost-agent", model_digest=MODEL, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, UNVERIFIABLE_DEPLOYMENT)
        ev = shadow_audit_event(v, system_id="ghost-agent")
        self.assertEqual(ev["event"], SHADOW_DETECTED_EVENT)

    def test_detect_shadow_digest_mismatch(self):
        reg = make_registry()
        register(reg)
        v = reg.detect_shadow(system_id="welfare-screener-1",
                              model_digest="99" * 32, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("mismatch", v.reason)

    def test_detect_shadow_matching_invocation(self):
        reg = make_registry()
        register(reg)
        v = reg.detect_shadow(system_id="welfare-screener-1",
                              model_digest=MODEL, now=T0)
        self.assertTrue(v.allowed)

    def test_retention_change_is_receipted(self):
        reg = make_registry()
        register(reg)
        ch = reg.change_retention_floor(
            authority_secret=AUTHORITY_SECRET, authority_id="reg-authority",
            system_id="welfare-screener-1", new_floor_days=365, changed_at=T0)
        self.assertEqual(ch.old_floor_days, 180)
        self.assertEqual(ch.new_floor_days, 365)
        ok, reason = reg.verify_chain()
        self.assertTrue(ok, reason)

    def test_retention_change_enforced_at_gate(self):
        reg = make_registry()
        r = register(reg)
        reg.change_retention_floor(
            authority_secret=AUTHORITY_SECRET, authority_id="reg-authority",
            system_id="welfare-screener-1", new_floor_days=365, changed_at=T0)
        v = reg.gate_deployment(receipt=r, intended_use="high",
                               log_retention_days=180, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("below floor", v.reason)

    def test_retention_change_unknown_system(self):
        reg = make_registry()
        with self.assertRaises(DeploymentRegistryError):
            reg.change_retention_floor(
                authority_secret=AUTHORITY_SECRET, authority_id="reg-authority",
                system_id="nope", new_floor_days=10, changed_at=T0)

    def test_explain_decision_high_risk(self):
        reg = make_registry()
        register(reg)
        expl = reg.explain_decision(system_id="welfare-screener-1")
        self.assertIsNotNone(expl)
        self.assertEqual(expl["appeal_path"], EXPLAIN["appeal_path"])
        self.assertEqual(expl["receipt_digest"],
                         reg._latest_by_system["welfare-screener-1"].receipt_digest)

    def test_explain_decision_non_high_returns_none(self):
        reg = make_registry()
        register(reg, system_id="chatbot", risk_class="limited",
                 fria_digest=None, explanation_fields={})
        self.assertIsNone(reg.explain_decision(system_id="chatbot"))
        self.assertIsNone(reg.explain_decision(system_id="ghost"))

    def test_audit_event_shape(self):
        reg = make_registry()
        r = register(reg)
        v = reg.gate_deployment(receipt=r, intended_use="high",
                               log_retention_days=180, now=T0)
        ev = deployment_audit_event(v, action="deploy")
        self.assertEqual(ev["event"], "deployment.registered_allowed")
        self.assertTrue(ev["allowed"])
        v2 = reg.gate_deployment(receipt=None, intended_use="high",
                                log_retention_days=180, now=T0)
        ev2 = deployment_audit_event(v2, action="deploy")
        self.assertEqual(ev2["event"], DEPLOYMENT_DENIED_EVENT)
        self.assertFalse(ev2["allowed"])

    def test_malformed_inputs_raise(self):
        reg = make_registry()
        with self.assertRaises(DeploymentRegistryError):
            register(reg, system_id="")
        with self.assertRaises(DeploymentRegistryError):
            register(reg, model_digest="not-hex")
        with self.assertRaises(DeploymentRegistryError):
            register(reg, retention_floor_days=-1)


if __name__ == "__main__":
    unittest.main()
