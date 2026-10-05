"""Tests for the 140th-batch underwriting & claims discipline gates."""

from __future__ import annotations

import unittest

import ed25519

import underwriting_agents as uw


def _keypair(seed: int) -> tuple[bytes, str]:
    secret = bytes([(seed + i) % 256 for i in range(32)])
    if all(b == 0 for b in secret):
        secret = b"\x01" * 32
    public = ed25519.public_key(secret)
    return secret, public.hex()


_REVIEWER = _keypair(11)
_AUTHORITY = _keypair(22)
_VENDOR = _keypair(33)
DIGEST = "ab" * 32
NOW = 1790000000  # after Art.50 deadline 2026-08-02, before Annex III 2027-12-02


def _breaker(now: int = NOW, kind: str = "claim_denial", payout_bps: int = 0) -> uw.BreakerReceipt:
    return uw.issue_breaker_receipt(
        break_id="brk-1",
        decision_id="dec-1",
        decision_digest=DIGEST,
        breaker_kind=kind,
        human_reviewer_id="rev-1",
        reviewer_pubkey_hex=_REVIEWER[1],
        reviewer_secret=_REVIEWER[0],
        payout_bps=payout_bps,
        created_at=now - 100,
        expires_at=now + 100,
    )


def _stress(now: int = NOW, disparity_bps: int = 100) -> uw.StressReceipt:
    return uw.issue_stress_receipt(
        template_id="tpl-1",
        template_digest=DIGEST,
        stress_test_digest=DIGEST,
        fairness_threshold_bps=200,
        measured_disparity_bps=disparity_bps,
        authority_id="auth-1",
        authority_pubkey_hex=_AUTHORITY[1],
        authority_secret=_AUTHORITY[0],
        tested_at=now - 100,
        expires_at=now + 100,
    )


def _vendor(now: int = NOW, evidence: str | None = DIGEST) -> uw.VendorClaim:
    return uw.issue_vendor_claim(
        claim_id="vc-1",
        vendor_id="vend-1",
        metric_name="accuracy",
        metric_value_bps=9970,
        evidence_digest=evidence,
        vendor_pubkey_hex=_VENDOR[1],
        vendor_secret=_VENDOR[0],
        claimed_at=now - 10,
    )


class EngineTest(unittest.TestCase):
    def test_approve_ok(self):
        self.assertTrue(uw.approve_only_engine("approve").allowed)

    def test_route_to_human_ok(self):
        self.assertTrue(uw.approve_only_engine("route_to_human").allowed)

    def test_deny_hard_denies(self):
        v = uw.approve_only_engine("deny")
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, uw.DENY_AI_DENIAL)

    def test_unknown_action_raises(self):
        with self.assertRaises(uw.UnderwritingError):
            uw.approve_only_engine("explode")


class BreakerTest(unittest.TestCase):
    def test_live_breaker_ok(self):
        v = uw.human_circuit_breaker(_breaker(), expected_kind="claim_denial", decision_digest=DIGEST, now=NOW)
        self.assertTrue(v.allowed)

    def test_tampered_signature_denies(self):
        r = _breaker()
        tampered = uw.BreakerReceipt(
            break_id=r.break_id, decision_id=r.decision_id, decision_digest=r.decision_digest,
            breaker_kind=r.breaker_kind, human_reviewer_id=r.human_reviewer_id,
            reviewer_pubkey_hex=r.reviewer_pubkey_hex, payout_bps=r.payout_bps,
            created_at=r.created_at, expires_at=r.expires_at,
            signature_hex="00" * 64, prev_digest=r.prev_digest,
        )
        v = uw.human_circuit_breaker(tampered, expected_kind="claim_denial", decision_digest=DIGEST, now=NOW)
        self.assertEqual(v.reason, uw.DENY_BREAKER_TAMPERED)

    def test_expired_denies(self):
        r = _breaker(now=NOW - 1000)
        v = uw.human_circuit_breaker(r, expected_kind="claim_denial", decision_digest=DIGEST, now=NOW)
        self.assertEqual(v.reason, uw.DENY_BREAKER_EXPIRED)

    def test_kind_mismatch_denies(self):
        v = uw.human_circuit_breaker(_breaker(kind="large_payout"), expected_kind="claim_denial", decision_digest=DIGEST, now=NOW)
        self.assertEqual(v.reason, uw.DENY_BREAKER_KIND_MISMATCH)

    def test_digest_mismatch_denies(self):
        v = uw.human_circuit_breaker(_breaker(), expected_kind="claim_denial", decision_digest="cd" * 32, now=NOW)
        self.assertEqual(v.reason, uw.DENY_BREAKER_TAMPERED)

    def test_denial_always_requires_breaker(self):
        self.assertTrue(uw.breaker_required("claim_denial", payout_bps=0))

    def test_small_payout_no_breaker(self):
        self.assertFalse(uw.breaker_required("large_payout", payout_bps=100))


class StressTest(unittest.TestCase):
    def test_live_receipt_ok(self):
        v = uw.fairness_stress_receipt(_stress(), template_digest=DIGEST, now=NOW)
        self.assertTrue(v.allowed)

    def test_missing_receipt_denies(self):
        v = uw.fairness_stress_receipt(None, template_digest=DIGEST, now=NOW)
        self.assertEqual(v.reason, uw.DENY_UNTESTED_TEMPLATE)

    def test_disparity_over_threshold_denies(self):
        v = uw.fairness_stress_receipt(_stress(disparity_bps=300), template_digest=DIGEST, now=NOW)
        self.assertEqual(v.reason, uw.DENY_UNTESTED_TEMPLATE)

    def test_expired_denies(self):
        v = uw.fairness_stress_receipt(_stress(now=NOW - 1000), template_digest=DIGEST, now=NOW)
        self.assertEqual(v.reason, uw.DENY_STRESS_EXPIRED)

    def test_template_digest_mismatch_denies(self):
        v = uw.fairness_stress_receipt(_stress(), template_digest="cd" * 32, now=NOW)
        self.assertEqual(v.reason, uw.DENY_STRESS_TEMPLATE_MISMATCH)


class ClockTest(unittest.TestCase):
    def test_all_met_ok(self):
        v = uw.ai_act_clock("d1", deployment_kind="underwriting",
                            obligations_met={"art50_transparency": True, "annex3_obligations": True}, now=NOW)
        self.assertTrue(v.allowed)
        self.assertEqual(v.pending_obligations, ())

    def test_future_deadline_pending(self):
        v = uw.ai_act_clock("d1", deployment_kind="underwriting",
                            obligations_met={"art50_transparency": True}, now=NOW)
        self.assertTrue(v.allowed)
        self.assertEqual(v.pending_obligations, ("annex3_obligations",))

    def test_lapsed_art50_denies(self):
        v = uw.ai_act_clock("d1", deployment_kind="claims_adjudication",
                            obligations_met={}, now=uw.ART50_TRANSPARENCY_EPOCH + 1)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, uw.DENY_COMPLIANCE_LAPSE)

    def test_before_any_deadline_ok(self):
        v = uw.ai_act_clock("d1", deployment_kind="pricing",
                            obligations_met={}, now=uw.ART50_TRANSPARENCY_EPOCH - 1)
        self.assertTrue(v.allowed)


class FraudProbeTest(unittest.TestCase):
    def test_route_to_human_ok(self):
        v = uw.synthetic_fraud_probe("fp-1", routed_action="route_to_human")
        self.assertTrue(v.allowed)

    def test_auto_deny_hard_denies(self):
        v = uw.synthetic_fraud_probe("fp-1", routed_action="deny")
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, uw.DENY_FRAUD_AUTO_DENY)

    def test_unknown_action_raises(self):
        with self.assertRaises(uw.UnderwritingError):
            uw.synthetic_fraud_probe("fp-1", routed_action="auto_approve")


class CreepTest(unittest.TestCase):
    def test_assistive_no_decision_ok(self):
        v = uw.assist_not_decide("s1", declared_assistive=True, decision_made=False)
        self.assertTrue(v.allowed)

    def test_assistive_that_decided_denies(self):
        v = uw.assist_not_decide("s1", declared_assistive=True, decision_made=True)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, uw.DENY_DECISION_CREEP)

    def test_declared_decisive_not_this_gate(self):
        v = uw.assist_not_decide("s1", declared_assistive=False, decision_made=True)
        self.assertTrue(v.allowed)


class MappingTest(unittest.TestCase):
    def test_mapped_high_risk_ok(self):
        v = uw.evaluation_tool_mapping("d1", deployment_kind="underwriting",
                                       mapped_items=["human_oversight", "claims_specific_review"])
        self.assertTrue(v.allowed)
        self.assertFalse(v.non_authoritative)

    def test_unmapped_high_risk_denies(self):
        v = uw.evaluation_tool_mapping("d1", deployment_kind="claims_adjudication", mapped_items=[])
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, uw.DENY_UNMAPPED_HIGH_RISK)

    def test_unmapped_low_risk_nonauth(self):
        v = uw.evaluation_tool_mapping("d1", deployment_kind="marketing_copy", mapped_items=[])
        self.assertTrue(v.allowed)
        self.assertTrue(v.non_authoritative)

    def test_unknown_item_raises(self):
        with self.assertRaises(uw.UnderwritingError):
            uw.evaluation_tool_mapping("d1", deployment_kind="underwriting", mapped_items=["vibes"])


class VendorTest(unittest.TestCase):
    def test_bound_evidence_ok(self):
        v = uw.vendor_disclosure_gate(_vendor(), now=NOW)
        self.assertTrue(v.allowed)
        self.assertFalse(v.non_authoritative)

    def test_self_reported_nonauth(self):
        v = uw.vendor_disclosure_gate(_vendor(evidence=None), now=NOW)
        self.assertTrue(v.allowed)
        self.assertTrue(v.non_authoritative)
        self.assertEqual(v.reason, uw.NONAUTH_VENDER_NO_EVIDENCE)

    def test_tampered_denies(self):
        c = _vendor()
        tampered = uw.VendorClaim(
            claim_id=c.claim_id, vendor_id=c.vendor_id, metric_name=c.metric_name,
            metric_value_bps=c.metric_value_bps, evidence_digest=c.evidence_digest,
            vendor_pubkey_hex=c.vendor_pubkey_hex, claimed_at=c.claimed_at,
            signature_hex="00" * 64, prev_digest=c.prev_digest,
        )
        v = uw.vendor_disclosure_gate(tampered, now=NOW)
        self.assertEqual(v.reason, uw.DENY_VENDOR_TAMPERED)

    def test_audit_event_shapes(self):
        v = uw.approve_only_engine("approve")
        ev = uw.engine_audit_event(v)
        self.assertEqual(ev["event"], uw.ENGINE_ALLOWED_EVENT)


if __name__ == "__main__":
    unittest.main()
