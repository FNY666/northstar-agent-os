"""Tests for the telecom AI discipline batch (one-hundred-twenty-ninth)."""

import os
import sys
import unittest

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

import ed25519
import telecom_agents as t

T0 = 1_700_000_000
AUTH = bytes([7]) * 32
PUB = ed25519.public_key(AUTH).hex()
CALLEE = bytes([13]) * 32
CALLEE_PUB = ed25519.public_key(CALLEE).hex()


class TelecomTestBase(unittest.TestCase):
    def assertDeny(self, verdict, code):
        self.assertFalse(verdict.allowed)
        self.assertIn(code, verdict.reason)

    def assertAllow(self, verdict):
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, t.AUTHORITATIVE)


class IdentityDisclosureTest(TelecomTestBase):
    def setUp(self):
        self.reg = t.IdentityRegistry()

    def _issue(self, session="s1", mode="visible"):
        return self.reg.issue_disclosure(
            disclosure_id=f"d-{session}-{mode}",
            session_id=session,
            bot_id="bot-1",
            disclosure_mode=mode,
            disclosed_at=T0,
            authority_pubkey_hex=PUB,
            authority_secret=AUTH,
        )

    def test_visible_disclosure_allows(self):
        v = t.identity_disclosure_gate(self._issue())
        self.assertAllow(v)

    def test_terms_only_denies_hidden_identity(self):
        v = t.identity_disclosure_gate(self._issue(mode="terms_only"))
        self.assertDeny(v, t.DENY_HIDDEN_IDENTITY)

    def test_bad_signature_denies(self):
        d = self._issue()
        tampered = t.IdentityDisclosure(
            disclosure_id=d.disclosure_id,
            session_id=d.session_id,
            bot_id="impersonator",
            disclosure_mode="visible",
            disclosed_at=d.disclosed_at,
            authority_pubkey_hex=d.authority_pubkey_hex,
            signature_hex=d.signature_hex,
            prev_digest=d.prev_digest,
            receipt_digest=d.receipt_digest,
        )
        v = t.identity_disclosure_gate(tampered)
        self.assertDeny(v, t.DENY_HIDDEN_IDENTITY)


class HumanDoorTest(TelecomTestBase):
    def setUp(self):
        self.reg = t.HumanDoorRegistry()

    def _issue(self, open_=True):
        return self.reg.issue_door(
            door_id="door-1",
            session_id="s1",
            human_channel_id="voice-queue-a",
            estimated_wait_s=180,
            door_open=open_,
            checked_at=T0,
            authority_pubkey_hex=PUB,
            authority_secret=AUTH,
        )

    def test_open_door_allows(self):
        v = t.human_door_receipt(self._issue())
        self.assertAllow(v)

    def test_no_door_denies(self):
        v = t.human_door_receipt(None)
        self.assertDeny(v, t.DENY_NO_HUMAN_DOOR)

    def test_closed_door_denies(self):
        v = t.human_door_receipt(self._issue(open_=False))
        self.assertDeny(v, t.DENY_NO_HUMAN_DOOR)


class SpamFlagTest(TelecomTestBase):
    def setUp(self):
        self.reg = t.SpamFlagRegistry()
        self.flag = self.reg.issue_flag(
            flag_id="flag-1",
            flagged_number="+8613800000001",
            flag_threshold_digest="aa" * 32,
            evidence_digest="bb" * 32,
            appeal_window_s=t.DEFAULT_APPEAL_WINDOW_S,
            flagged_at=T0,
            authority_pubkey_hex=PUB,
            authority_secret=AUTH,
        )

    def test_disconnect_before_window_denies(self):
        v = t.spam_flag_receipt(
            self.flag, registry=self.reg, threshold_met=True, now=T0
        )
        self.assertDeny(v, t.DENY_APPEAL_PENDING)

    def test_threshold_unmet_denies(self):
        v = t.spam_flag_receipt(
            self.flag,
            registry=self.reg,
            threshold_met=False,
            now=T0 + t.DEFAULT_APPEAL_WINDOW_S + 1,
        )
        self.assertDeny(v, t.DENY_THRESHOLD_UNMET)

    def test_disconnect_after_window_allows(self):
        v = t.spam_flag_receipt(
            self.flag,
            registry=self.reg,
            threshold_met=True,
            now=T0 + t.DEFAULT_APPEAL_WINDOW_S + 1,
        )
        self.assertAllow(v)

    def test_appeal_pending_denies(self):
        self.reg.file_appeal("flag-1")
        v = t.spam_flag_receipt(
            self.flag,
            registry=self.reg,
            threshold_met=True,
            now=T0 + t.DEFAULT_APPEAL_WINDOW_S + 1,
        )
        self.assertDeny(v, t.DENY_APPEAL_PENDING)

    def test_misflag_revocation_denies_as_harm(self):
        self.reg.file_appeal("flag-1")
        self.reg.revoke_flag("flag-1")
        v = t.spam_flag_receipt(
            self.flag,
            registry=self.reg,
            threshold_met=True,
            now=T0 + t.DEFAULT_APPEAL_WINDOW_S + 1,
        )
        self.assertDeny(v, t.DENY_MISFLAG_HARM)


class A2PConsentTest(TelecomTestBase):
    def setUp(self):
        self.reg = t.A2PConsentRegistry()
        self.reg.issue_consent(
            consent_id="c1",
            caller_id="carrier-a",
            callee_id="+8613800000002",
            purpose="fraud-alert",
            consented_at=T0,
            expires_at=T0 + 86_400,
            callee_pubkey_hex=CALLEE_PUB,
            callee_secret=CALLEE,
        )

    def test_live_consent_allows(self):
        v = t.a2p_consent_receipt(
            caller_id="carrier-a",
            callee_id="+8613800000002",
            purpose="fraud-alert",
            registry=self.reg,
            now=T0 + 100,
        )
        self.assertAllow(v)

    def test_no_consent_denies_robocall(self):
        v = t.a2p_consent_receipt(
            caller_id="carrier-a",
            callee_id="+8613800000009",
            purpose="fraud-alert",
            registry=self.reg,
            now=T0 + 100,
        )
        self.assertDeny(v, t.DENY_UNCONSENTED_ROBOCALL)

    def test_wrong_purpose_denies(self):
        v = t.a2p_consent_receipt(
            caller_id="carrier-a",
            callee_id="+8613800000002",
            purpose="marketing",
            registry=self.reg,
            now=T0 + 100,
        )
        self.assertDeny(v, t.DENY_UNCONSENTED_ROBOCALL)

    def test_expired_consent_denies(self):
        v = t.a2p_consent_receipt(
            caller_id="carrier-a",
            callee_id="+8613800000002",
            purpose="fraud-alert",
            registry=self.reg,
            now=T0 + 86_400 + 1,
        )
        self.assertDeny(v, t.DENY_UNCONSENTED_ROBOCALL)

    def test_revoked_consent_denies(self):
        self.reg.revoke("c1")
        v = t.a2p_consent_receipt(
            caller_id="carrier-a",
            callee_id="+8613800000002",
            purpose="fraud-alert",
            registry=self.reg,
            now=T0 + 100,
        )
        self.assertDeny(v, t.DENY_UNCONSENTED_ROBOCALL)


class NetworkEnvelopeTest(TelecomTestBase):
    def setUp(self):
        self.reg = t.NetworkEnvelopeRegistry()
        self.env = self.reg.arm_envelope(
            envelope_id="env-1",
            network_element_id="gnb-42",
            allowed_actions=["reroute", "capacity_adjust"],
            armed_at=T0,
            expires_at=T0 + 3_600,
            authority_pubkey_hex=PUB,
            authority_secret=AUTH,
        )

    def test_in_envelope_allows(self):
        v = t.network_action_envelope(
            envelope=self.env,
            action="reroute",
            network_element_id="gnb-42",
            now=T0,
        )
        self.assertAllow(v)

    def test_outside_envelope_denies(self):
        v = t.network_action_envelope(
            envelope=self.env,
            action="parameter_change",
            network_element_id="gnb-42",
            now=T0,
        )
        self.assertDeny(v, t.DENY_OUTSIDE_NETWORK_ENVELOPE)

    def test_wrong_element_denies(self):
        v = t.network_action_envelope(
            envelope=self.env,
            action="reroute",
            network_element_id="gnb-99",
            now=T0,
        )
        self.assertDeny(v, t.DENY_OUTSIDE_NETWORK_ENVELOPE)

    def test_no_envelope_denies(self):
        v = t.network_action_envelope(
            envelope=None,
            action="reroute",
            network_element_id="gnb-42",
            now=T0,
        )
        self.assertDeny(v, t.DENY_OUTSIDE_NETWORK_ENVELOPE)

    def test_expired_envelope_denies(self):
        v = t.network_action_envelope(
            envelope=self.env,
            action="reroute",
            network_element_id="gnb-42",
            now=T0 + 3_600 + 1,
        )
        self.assertDeny(v, t.DENY_OUTSIDE_NETWORK_ENVELOPE)


class BillingSeparationTest(TelecomTestBase):
    def setUp(self):
        self.reg = t.BillingRegistry()
        self.reg.issue_receipt(
            receipt_id="br-1",
            bill_id="bill-1",
            account_id="acct-1",
            bill_digest="dd" * 32,
            engine_id="billing-engine",
            engine_version="2.4.1",
            computed_at=T0,
            authority_pubkey_hex=PUB,
            authority_secret=AUTH,
        )

    def test_engine_receipt_allows(self):
        v = t.billing_logic_separation(
            bill_id="bill-1", registry=self.reg, computed_by_llm=False
        )
        self.assertAllow(v)

    def test_llm_computed_bill_denies(self):
        v = t.billing_logic_separation(
            bill_id="bill-1", registry=self.reg, computed_by_llm=True
        )
        self.assertDeny(v, t.DENY_LLM_BILLING)


class SignalingPurposeTest(TelecomTestBase):
    def setUp(self):
        self.reg = t.SignalingRegistry()
        self.reg.issue_grant(
            grant_id="g1",
            subject_id="sub-1",
            purpose="network_planning",
            dataset_digest="ee" * 32,
            granted_at=T0,
            expires_at=T0 + 86_400,
            subject_pubkey_hex=CALLEE_PUB,
            subject_secret=CALLEE,
        )

    def test_matching_purpose_allows(self):
        v = t.signaling_purpose_binding(
            subject_id="sub-1",
            purpose="network_planning",
            dataset_digest="ee" * 32,
            registry=self.reg,
            now=T0 + 10,
        )
        self.assertAllow(v)

    def test_repurpose_denies(self):
        v = t.signaling_purpose_binding(
            subject_id="sub-1",
            purpose="fraud_detection",
            dataset_digest="ee" * 32,
            registry=self.reg,
            now=T0 + 10,
        )
        self.assertDeny(v, t.DENY_SIGNALING_REPURPOSE)


class OutageEtaTest(TelecomTestBase):
    def setUp(self):
        self.reg = t.OutageEtaRegistry()
        self.eta = self.reg.issue_eta(
            eta_id="eta-1",
            outage_id="out-1",
            network_state_digest="cc" * 32,
            eta_epoch=T0 + 7_200,
            issued_at=T0,
            ttl_s=t.DEFAULT_ETA_TTL_S,
            authority_pubkey_hex=PUB,
            authority_secret=AUTH,
        )

    def test_fresh_eta_allows(self):
        v = t.outage_eta_receipt(
            self.eta, expected_state_digest="cc" * 32, now=T0
        )
        self.assertAllow(v)

    def test_expired_eta_non_authoritative(self):
        v = t.outage_eta_receipt(
            self.eta, expected_state_digest="cc" * 32, now=T0 + 7_200
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, t.NON_AUTHORITATIVE)
        self.assertIn(t.DENY_STALE_ETA, v.reason)

    def test_state_moved_on_denies(self):
        v = t.outage_eta_receipt(
            self.eta, expected_state_digest="ff" * 32, now=T0
        )
        self.assertDeny(v, t.DENY_STALE_ETA)

    def test_no_eta_denies(self):
        v = t.outage_eta_receipt(None, now=T0)
        self.assertDeny(v, t.DENY_STALE_ETA)


if __name__ == "__main__":
    unittest.main()
