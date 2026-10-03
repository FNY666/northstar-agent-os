"""Tests for the one-hundred-forty-seventh batch: government-service AI discipline."""

import unittest

import govservices_agents as gs
from govservices_agents import GovServicesError


AUTH = b"govservices-bench-auth-00000001x"  # 32 bytes
assert len(AUTH) == 32
HUMAN = b"govservices-human-signer-0000001"  # 32 bytes
assert len(HUMAN) == 32
AGENT_KEY = b"govservices-agent-identity-00001"  # 32 bytes
assert len(AGENT_KEY) == 32
T0 = 1_800_000_000
H64 = "ab" * 32


def decision(**kw):
    args = dict(
        decision_id="d-1",
        decision_kind="benefit_denial",
        beneficiary_ref_digest=H64,
        ai_recommendation_digest="cd" * 32,
        decided_at=T0,
    )
    args.update(kw)
    return gs.issue_decision_record(**args)


def exclusion_probe(**kw):
    args = dict(
        probe_id="p-1",
        service_id="svc-1",
        attempts_total=10_000,
        auth_failures=100,
        tolerance_bps=200,
        window_start=T0,
        window_end=T0 + 86_400,
        issuer_id="op-1",
        issuer_secret=AUTH,
    )
    args.update(kw)
    return gs.issue_exclusion_probe(**args)


def channel_receipt(**kw):
    args = dict(
        receipt_id="cr-1",
        service_id="svc-1",
        channels=("self_service_web", "in_person"),
        declared_at=T0,
        issuer_id="op-1",
        issuer_secret=AUTH,
    )
    args.update(kw)
    return gs.alternative_channel_receipt(**args)


def discretion_pin(**kw):
    args = dict(
        pin_id="dp-1",
        service_id="svc-1",
        act_kind="welfare_eligibility_review",
        ai_role="advisory_only",
        rationale_digest=H64,
        pinned_at=T0,
        issuer_id="op-1",
        issuer_secret=AUTH,
    )
    args.update(kw)
    return gs.issue_discretion_pin(**args)


def identity_pin(**kw):
    args = dict(
        pin_id="ip-1",
        service_id="svc-1",
        purpose="benefit_claim",
        needed_fields=("name", "date_of_birth", "address"),
        pinned_at=T0,
        issuer_id="op-1",
        issuer_secret=AUTH,
    )
    args.update(kw)
    return gs.issue_identity_pin(**args)


def urgency_passage(**kw):
    args = dict(
        passage_id="up-1",
        law_id="law-nz-2026",
        automation_expansion=True,
        passed_at=T0,
        scrutiny_window_s=86_400 * 90,
        issuer_id="op-1",
        issuer_secret=AUTH,
    )
    args.update(kw)
    return gs.issue_urgency_passage(**args)


def review_notice(**kw):
    args = dict(
        notice_id="n-1",
        beneficiary_ref_digest=H64,
        review_kind="benefit_reassessment",
        notice_issued_at=T0,
        appeal_deadline=T0 + 86_400 * 28,
        issuer_id="op-1",
        issuer_secret=AUTH,
    )
    args.update(kw)
    return gs.issue_review_notice(**args)


def fraud_flag(**kw):
    args = dict(
        flag_id="f-1",
        subject_ref_digest=H64,
        lead_digest="cd" * 32,
        referred_by="investigator-1",
        referred_at=T0,
        issuer_id="op-1",
        issuer_secret=AUTH,
    )
    args.update(kw)
    return gs.issue_fraud_flag(**args)


class HumanFinalGateTests(unittest.TestCase):
    def test_signed_denial_passes(self):
        r = decision(human_signer_id="officer-1", human_secret=HUMAN,
                     human_pubkey=ed25519_public_key(HUMAN))
        v = gs.human_final_gate(r)
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, "authoritative")

    def test_unsigned_denial_is_ai_denial(self):
        v = gs.human_final_gate(decision())
        self.assertFalse(v.allowed)
        self.assertIn("govservices.ai_denial", v.deny_code)

    def test_bad_signature_is_ai_denial(self):
        r = decision(human_signer_id="officer-1", human_secret=HUMAN,
                     human_pubkey=ed25519_public_key(HUMAN))
        bad = gs.DecisionRecord(**{**r.__dict__, "human_signature_hex": "00" * 64})
        v = gs.human_final_gate(bad)
        self.assertFalse(v.allowed)
        self.assertIn("govservices.ai_denial", v.deny_code)

    def test_non_adverse_needs_no_signature(self):
        r = decision(decision_kind="benefit_grant")
        v = gs.human_final_gate(r)
        self.assertTrue(v.allowed)

    def test_unknown_kind_is_programming_error(self):
        with self.assertRaises(GovServicesError):
            decision(decision_kind="mind_reading")

    def test_key_without_signer_refused(self):
        with self.assertRaises(GovServicesError):
            decision(human_secret=HUMAN, human_pubkey=ed25519_public_key(HUMAN))


def ed25519_public_key(secret: bytes) -> bytes:
    import ed25519 as _ed

    return _ed.public_key(secret)


class ExclusionMonitorTests(unittest.TestCase):
    def test_within_tolerance_passes(self):
        v = gs.exclusion_monitor(exclusion_probe())
        self.assertTrue(v.allowed)

    def test_over_tolerance_denies(self):
        v = gs.exclusion_monitor(exclusion_probe(auth_failures=700))
        self.assertFalse(v.allowed)
        self.assertIn("govservices.exclusion_gap", v.deny_code)

    def test_empty_window_is_programming_error(self):
        with self.assertRaises(GovServicesError):
            exclusion_probe(attempts_total=0)

    def test_failures_over_attempts_refused(self):
        with self.assertRaises(GovServicesError):
            exclusion_probe(attempts_total=10, auth_failures=11)


class ChannelGateTests(unittest.TestCase):
    def test_with_in_person_passes(self):
        v = gs.digital_only_gate(channel_receipt())
        self.assertTrue(v.allowed)

    def test_digital_only_denies(self):
        v = gs.digital_only_gate(channel_receipt(channels=("self_service_web", "mobile_app")))
        self.assertFalse(v.allowed)
        self.assertIn("govservices.digital_only", v.deny_code)

    def test_empty_channels_refused(self):
        with self.assertRaises(GovServicesError):
            channel_receipt(channels=())

    def test_unknown_channel_refused(self):
        with self.assertRaises(GovServicesError):
            channel_receipt(channels=("telepathy",))


class DiscretionPinTests(unittest.TestCase):
    def test_within_pin_passes(self):
        v = gs.discretion_pin(discretion_pin(), acted_as_role="advisory_only",
                              performed_act="welfare_eligibility_review")
        self.assertTrue(v.allowed)

    def test_role_wider_than_pin_denies(self):
        pin = discretion_pin()
        # decision_support is wider than advisory_only
        v = gs.discretion_pin(pin, acted_as_role="decision_support",
                              performed_act="welfare_eligibility_review")
        self.assertFalse(v.allowed)
        self.assertIn("govservices.discretion_breach", v.deny_code)

    def test_different_act_denies(self):
        v = gs.discretion_pin(discretion_pin(), acted_as_role="advisory_only",
                              performed_act="sanction_imposition")
        self.assertFalse(v.allowed)
        self.assertIn("govservices.discretion_breach", v.deny_code)


class IdentityMinimalityTests(unittest.TestCase):
    def test_minimal_disclosure_passes(self):
        v = gs.identity_minimality(identity_pin(), disclosed_fields=("name", "address"))
        self.assertTrue(v.allowed)

    def test_over_collection_denies(self):
        v = gs.identity_minimality(identity_pin(), disclosed_fields=("name", "biometric"))
        self.assertFalse(v.allowed)
        self.assertIn("govservices.identity_overreach", v.deny_code)

    def test_unknown_field_is_programming_error(self):
        with self.assertRaises(GovServicesError):
            gs.identity_minimality(identity_pin(), disclosed_fields=("retina_scan",))


class AgentIdentityTests(unittest.TestCase):
    def test_registered_agent_passes(self):
        reg = gs.AgentIdentityRegistry()
        reg.register("agent-1", AGENT_KEY, "operator-1", T0, "samr", AUTH)
        v = gs.agent_identity_registry(reg, agent_id="agent-1")
        self.assertTrue(v.allowed)

    def test_unregistered_agent_denies(self):
        v = gs.agent_identity_registry(gs.AgentIdentityRegistry(), agent_id="ghost-1")
        self.assertFalse(v.allowed)
        self.assertIn("govservices.unregistered_agent", v.deny_code)

    def test_double_registration_refused(self):
        reg = gs.AgentIdentityRegistry()
        reg.register("agent-1", AGENT_KEY, "operator-1", T0, "samr", AUTH)
        with self.assertRaises(GovServicesError):
            reg.register("agent-1", AGENT_KEY, "operator-1", T0, "samr", AUTH)


class UrgencyClockTests(unittest.TestCase):
    def test_scrutiny_before_deadline_passes(self):
        passage = urgency_passage()
        receipt = gs.issue_scrutiny_receipt(
            receipt_id="s-1", law_id="law-nz-2026", findings_digest=H64,
            reviewed_at=T0 + 86_400, issuer_id="op-1", issuer_secret=AUTH)
        v = gs.urgency_scrutiny_clock(passage, (receipt,), now=T0 + 86_400 * 200)
        self.assertTrue(v.allowed)

    def test_overdue_without_scrutiny_denies(self):
        passage = urgency_passage()
        v = gs.urgency_scrutiny_clock(passage, (), now=T0 + 86_400 * 200)
        self.assertFalse(v.allowed)
        self.assertIn("govservices.scrutiny_overdue", v.deny_code)

    def test_within_window_passes(self):
        v = gs.urgency_scrutiny_clock(urgency_passage(), (), now=T0 + 86_400)
        self.assertTrue(v.allowed)

    def test_non_expansion_passage_is_fine(self):
        v = gs.urgency_scrutiny_clock(
            urgency_passage(automation_expansion=False), (),
            now=T0 + 86_400 * 500)
        self.assertTrue(v.allowed)


class BenefitClockTests(unittest.TestCase):
    def test_suspension_before_appeal_deadline_denies(self):
        v = gs.benefit_clock(review_notice(), attempted_at=T0 + 86_400 * 7,
                             appeal_status="pending")
        self.assertFalse(v.allowed)
        self.assertIn("govservices.suspension_before_appeal", v.deny_code)

    def test_suspension_after_deadline_expired_passes(self):
        v = gs.benefit_clock(review_notice(), attempted_at=T0 + 86_400 * 60,
                             appeal_status="none_filed_expired")
        self.assertTrue(v.allowed)

    def test_overturned_appeal_blocks_suspension(self):
        v = gs.benefit_clock(review_notice(), attempted_at=T0 + 86_400 * 60,
                             appeal_status="resolved_overturned")
        self.assertFalse(v.allowed)
        self.assertIn("govservices.suspension_before_appeal", v.deny_code)

    def test_zero_appeal_window_refused(self):
        with self.assertRaises(GovServicesError):
            gs.issue_review_notice(
                notice_id="n-x", beneficiary_ref_digest=H64,
                review_kind="benefit_reassessment",
                notice_issued_at=T0, appeal_deadline=T0,
                issuer_id="op-1", issuer_secret=AUTH)


class FraudFlagTests(unittest.TestCase):
    def test_flag_as_lead_passes(self):
        v = gs.fraud_flag_receipt(fraud_flag(), treated_as_determination=False)
        self.assertTrue(v.allowed)

    def test_flag_as_determination_denies(self):
        v = gs.fraud_flag_receipt(fraud_flag(), treated_as_determination=True)
        self.assertFalse(v.allowed)
        self.assertIn("govservices.flag_fraud", v.deny_code)

    def test_non_bool_treatment_is_programming_error(self):
        with self.assertRaises(GovServicesError):
            gs.fraud_flag_receipt(fraud_flag(), treated_as_determination="yes")


if __name__ == "__main__":
    unittest.main()
