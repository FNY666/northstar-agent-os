"""Tests for eldercare_agents (one-hundred-sixty-first batch)."""

from __future__ import annotations

import os
import sys
import unittest

import ed25519

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from eldercare_agents import (
    AudioRetentionRegistry,
    ConsentChain,
    ConsentChainRegistry,
    ContactFloorReport,
    ConstraintAction,
    EmotionSignal,
    FalseAlarmChannel,
    FalseAlarmRegistry,
    MonitoringRegistry,
    PreventionEvidenceRegistry,
    StaffingFloorRegistry,
    VideoStreamConfig,
    VoiceImpersonationRegistry,
    avatar_anonymization,
    care_false_alarm_budget,
    check_audio_retention,
    check_consent_chain,
    check_contact_floor,
    check_emotion_boundary,
    check_false_alarm_budget,
    check_monitoring_mode,
    check_prevention_evidence,
    check_staffing_floor,
    check_video_stream,
    check_voice_impersonation,
    human_contact_floor,
    no_audio_retention_pin,
    staff_augmentation_floor,
    surveillance_not_prevention,
    MODE_ANOMALY_ONLY,
    MODE_ALWAYS_WATCH,
    PARTY_FAMILY,
    PARTY_PROFESSIONAL,
    PARTY_RESIDENT,
    CONSENT_SCOPE_MONITORING,
    CONSENT_SCOPE_VIDEO,
    CLASS_ALLOW,
    CLASS_DENY,
    CLASS_MINIMAL_INTRUSION,
    EldercareError,
)

SEC_A = bytes.fromhex("aa" * 32)
SEC_B = bytes.fromhex("bb" * 32)
PUB_A = ed25519.public_key(SEC_A).hex()
PUB_B = ed25519.public_key(SEC_B).hex()
T0 = 1_800_000_000
H64 = "ab" * 32


def _chain3(registry: ConsentChainRegistry, scope=CONSENT_SCOPE_MONITORING):
    receipts = {}
    for party, sec in ((PARTY_RESIDENT, SEC_A), (PARTY_FAMILY, SEC_A), (PARTY_PROFESSIONAL, SEC_A)):
        receipts[party] = registry.issue(
            receipt_id=f"cr-{party}", resident_id="r1", party=party, scope=scope,
            data_types=("motion",), retention_days=90, consented_at=T0,
            proxy=(party == PARTY_RESIDENT), authority_secret=sec)
    return ConsentChain(resident_id="r1", receipts=receipts, withdrawals={})


class TestMonitoringMode(unittest.TestCase):
    def test_anomaly_only_is_default_allowed(self):
        reg = MonitoringRegistry([PUB_A])
        v = check_monitoring_mode(registry=reg, resident_id="r1", mode=MODE_ANOMALY_ONLY,
                                 opt_in=None, now=T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_ALLOW)

    def test_always_watch_without_opt_in_denied(self):
        reg = MonitoringRegistry([PUB_A])
        v = check_monitoring_mode(registry=reg, resident_id="r1", mode=MODE_ALWAYS_WATCH,
                                 opt_in=None, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("always_watch_without_opt_in", v.reason)

    def test_always_watch_with_live_opt_in_allowed(self):
        reg = MonitoringRegistry([PUB_A])
        opt = reg.issue_opt_in(receipt_id="m1", resident_id="r1", mode=MODE_ALWAYS_WATCH,
                               scope=CONSENT_SCOPE_MONITORING, opt_in_at=T0,
                               expires_at=T0 + 86_400, authority_secret=SEC_A)
        v = check_monitoring_mode(registry=reg, resident_id="r1", mode=MODE_ALWAYS_WATCH,
                                 opt_in=opt, now=T0 + 100)
        self.assertTrue(v.allowed)

    def test_expired_opt_in_denied(self):
        reg = MonitoringRegistry([PUB_A])
        opt = reg.issue_opt_in(receipt_id="m2", resident_id="r1", mode=MODE_ALWAYS_WATCH,
                               scope=CONSENT_SCOPE_MONITORING, opt_in_at=T0,
                               expires_at=T0 + 86_400, authority_secret=SEC_A)
        v = check_monitoring_mode(registry=reg, resident_id="r1", mode=MODE_ALWAYS_WATCH,
                                 opt_in=opt, now=T0 + 86_400)
        self.assertFalse(v.allowed)
        self.assertIn("opt_in_not_live", v.reason)

    def test_unknown_mode_denied(self):
        reg = MonitoringRegistry([PUB_A])
        v = check_monitoring_mode(registry=reg, resident_id="r1", mode="night_vision",
                                 opt_in=None, now=T0)
        self.assertFalse(v.allowed)


class TestConsentChain(unittest.TestCase):
    def test_full_chain_allowed(self):
        reg = ConsentChainRegistry([PUB_A])
        v = check_consent_chain(registry=reg, chain=_chain3(reg),
                                scope=CONSENT_SCOPE_MONITORING, now=T0 + 100)
        self.assertTrue(v.allowed)

    def test_withdrawal_drops_to_minimal_intrusion(self):
        reg = ConsentChainRegistry([PUB_A])
        chain = _chain3(reg)
        chain.withdrawals[PARTY_FAMILY] = T0 + 50
        v = check_consent_chain(registry=reg, chain=chain,
                                scope=CONSENT_SCOPE_MONITORING, now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_MINIMAL_INTRUSION)
        self.assertIn("consent_chain_broken", v.reason)

    def test_missing_party_denied(self):
        reg = ConsentChainRegistry([PUB_A])
        chain = _chain3(reg)
        del chain.receipts[PARTY_PROFESSIONAL]
        v = check_consent_chain(registry=reg, chain=chain,
                                scope=CONSENT_SCOPE_MONITORING, now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("professional", v.reason)

    def test_scope_mismatch_denied(self):
        reg = ConsentChainRegistry([PUB_A])
        chain = _chain3(reg, scope=CONSENT_SCOPE_MONITORING)
        v = check_consent_chain(registry=reg, chain=chain,
                                scope=CONSENT_SCOPE_VIDEO, now=T0 + 100)
        self.assertFalse(v.allowed)


class TestFalseAlarmBudget(unittest.TestCase):
    def test_within_budget_allowed(self):
        reg = FalseAlarmRegistry()
        reg.register(FalseAlarmChannel("ch1", "f1", budget_per_year=500, false_alarms=120,
                                       window_start=T0))
        v = check_false_alarm_budget(registry=reg, channel_id="ch1", now=T0)
        self.assertTrue(v.allowed)

    def test_exhausted_budget_denied(self):
        reg = FalseAlarmRegistry()
        reg.register(FalseAlarmChannel("ch2", "f1", budget_per_year=500, false_alarms=500,
                                       window_start=T0))
        v = check_false_alarm_budget(registry=reg, channel_id="ch2", now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("alarm_fatigue", v.reason)

    def test_unknown_channel_denied(self):
        reg = FalseAlarmRegistry()
        v = check_false_alarm_budget(registry=reg, channel_id="nope", now=T0)
        self.assertFalse(v.allowed)

    def test_care_false_alarm_budget_helper(self):
        self.assertEqual(care_false_alarm_budget(), 500)


class TestVoiceImpersonation(unittest.TestCase):
    def test_no_impersonation_allowed(self):
        reg = VoiceImpersonationRegistry([PUB_A, PUB_B])
        v = check_voice_impersonation(registry=reg, resident_id="r1",
                                      impersonates_real_person=False, disclosure=None,
                                      resident_cognitively_impaired=False, now=T0)
        self.assertTrue(v.allowed)

    def test_impersonation_without_disclosure_denied(self):
        reg = VoiceImpersonationRegistry([PUB_A, PUB_B])
        v = check_voice_impersonation(registry=reg, resident_id="r1",
                                      impersonates_real_person=True, disclosure=None,
                                      resident_cognitively_impaired=True, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("undisclosed_impersonation", v.reason)

    def test_impersonation_with_dual_sign_allowed(self):
        reg = VoiceImpersonationRegistry([PUB_A, PUB_B])
        d = reg.issue(receipt_id="vi1", resident_id="r1", impersonated_person="Bastien",
                      relationship="grandson", disclosure_text="这是AI模仿的Bastien的声音",
                      resident_cognitively_impaired=True, configured_at=T0,
                      family_secret=SEC_A, professional_secret=SEC_B)
        v = check_voice_impersonation(registry=reg, resident_id="r1",
                                      impersonates_real_person=True, disclosure=d,
                                      resident_cognitively_impaired=True, now=T0)
        self.assertTrue(v.allowed)

    def test_tampered_disclosure_denied(self):
        reg = VoiceImpersonationRegistry([PUB_A, PUB_B])
        d = reg.issue(receipt_id="vi2", resident_id="r1", impersonated_person="Bastien",
                      relationship="grandson", disclosure_text="这是AI模仿的Bastien的声音",
                      resident_cognitively_impaired=True, configured_at=T0,
                      family_secret=SEC_A, professional_secret=SEC_B)
        tampered = type(d)(**{**d.__dict__, "disclosure_text": "changed"})
        v = check_voice_impersonation(registry=reg, resident_id="r1",
                                      impersonates_real_person=True, disclosure=tampered,
                                      resident_cognitively_impaired=True, now=T0)
        self.assertFalse(v.allowed)


class TestVideoStream(unittest.TestCase):
    def test_avatar_default_allowed(self):
        v = check_video_stream(config=VideoStreamConfig("s1", "r1", avatar_anonymization(),
                                                        False, "family"))
        self.assertTrue(v.allowed)

    def test_blurred_allowed(self):
        v = check_video_stream(config=VideoStreamConfig("s2", "r1", "blurred", False, "vendor"))
        self.assertTrue(v.allowed)

    def test_raw_event_triggered_staff_allowed(self):
        v = check_video_stream(config=VideoStreamConfig("s3", "r1", "raw", True, "staff"))
        self.assertTrue(v.allowed)

    def test_raw_to_vendor_denied(self):
        v = check_video_stream(config=VideoStreamConfig("s4", "r1", "raw", True, "vendor"))
        self.assertFalse(v.allowed)
        self.assertIn("raw_video_without_event_or_authority", v.reason)

    def test_raw_not_event_triggered_denied(self):
        v = check_video_stream(config=VideoStreamConfig("s5", "r1", "raw", False, "family"))
        self.assertFalse(v.allowed)


class TestAudioRetention(unittest.TestCase):
    def test_no_retention_allowed(self):
        reg = AudioRetentionRegistry([PUB_A])
        v = check_audio_retention(registry=reg, resident_id="r1", retains_audio=False,
                                 receipt=None, now=T0)
        self.assertTrue(v.allowed)

    def test_retention_without_consent_denied(self):
        reg = AudioRetentionRegistry([PUB_A])
        v = check_audio_retention(registry=reg, resident_id="r1", retains_audio=True,
                                 receipt=None, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("audio_retention_without_consent", v.reason)

    def test_retention_with_live_receipt_allowed(self):
        reg = AudioRetentionRegistry([PUB_A])
        r = reg.issue(receipt_id="ar1", resident_id="r1", retention_days=30,
                      consented_at=T0, expires_at=T0 + 30 * 86_400, authority_secret=SEC_A)
        v = check_audio_retention(registry=reg, resident_id="r1", retains_audio=True,
                                 receipt=r, now=T0 + 100)
        self.assertTrue(v.allowed)

    def test_expired_retention_receipt_denied(self):
        reg = AudioRetentionRegistry([PUB_A])
        r = reg.issue(receipt_id="ar2", resident_id="r1", retention_days=30,
                      consented_at=T0, expires_at=T0 + 86_400, authority_secret=SEC_A)
        v = check_audio_retention(registry=reg, resident_id="r1", retains_audio=True,
                                 receipt=r, now=T0 + 86_400)
        self.assertFalse(v.allowed)
        self.assertIn("not_live", v.reason)

    def test_no_audio_retention_pin(self):
        self.assertEqual(no_audio_retention_pin(), "no_retention")


class TestPreventionEvidence(unittest.TestCase):
    def test_no_claim_allowed(self):
        reg = PreventionEvidenceRegistry([PUB_A])
        v = check_prevention_evidence(registry=reg, claim=None, claims_prevention=False)
        self.assertTrue(v.allowed)

    def test_claim_without_evidence_denied(self):
        reg = PreventionEvidenceRegistry([PUB_A])
        v = check_prevention_evidence(registry=reg, claim=None, claims_prevention=True)
        self.assertFalse(v.allowed)
        self.assertIn("without_evidence", v.reason)

    def test_vendor_only_study_denied(self):
        reg = PreventionEvidenceRegistry([PUB_A])
        c = reg.issue(claim_id="pc1", claim_text="reduces falls 40%",
                      claimed_reduction_bps=4000, study_digest=H64,
                      independent=False, issued_at=T0, authority_secret=SEC_A)
        v = check_prevention_evidence(registry=reg, claim=c, claims_prevention=True)
        self.assertFalse(v.allowed)
        self.assertIn("unverified_prevention_claim", v.reason)

    def test_independent_study_allowed(self):
        reg = PreventionEvidenceRegistry([PUB_A])
        c = reg.issue(claim_id="pc2", claim_text="reduces falls 40%",
                      claimed_reduction_bps=4000, study_digest=H64,
                      independent=True, issued_at=T0, authority_secret=SEC_A)
        v = check_prevention_evidence(registry=reg, claim=c, claims_prevention=True)
        self.assertTrue(v.allowed)

    def test_surveillance_not_prevention_tag(self):
        self.assertEqual(surveillance_not_prevention(), "surveillance_is_not_prevention")


class TestStaffingFloor(unittest.TestCase):
    def test_no_contract_denied(self):
        reg = StaffingFloorRegistry([PUB_A])
        v = check_staffing_floor(registry=reg, contract=None, roster_hours_per_week=200, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_staffing_floor_contract", v.reason)

    def test_roster_below_floor_denied(self):
        reg = StaffingFloorRegistry([PUB_A])
        c = reg.issue(receipt_id="sf1", facility_id="f1", floor_hours_per_week=200,
                      baseline_hours_per_week=200, effective_from=T0, authority_secret=SEC_A)
        v = check_staffing_floor(registry=reg, contract=c, roster_hours_per_week=150, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("staffing_floor_breach", v.reason)

    def test_floor_below_baseline_denied(self):
        reg = StaffingFloorRegistry([PUB_A])
        c = reg.issue(receipt_id="sf2", facility_id="f1", floor_hours_per_week=150,
                      baseline_hours_per_week=200, effective_from=T0, authority_secret=SEC_A)
        v = check_staffing_floor(registry=reg, contract=c, roster_hours_per_week=200, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("below_baseline", v.reason)

    def test_floor_satisfied_allowed(self):
        reg = StaffingFloorRegistry([PUB_A])
        c = reg.issue(receipt_id="sf3", facility_id="f1", floor_hours_per_week=200,
                      baseline_hours_per_week=200, effective_from=T0, authority_secret=SEC_A)
        v = check_staffing_floor(registry=reg, contract=c, roster_hours_per_week=220, now=T0)
        self.assertTrue(v.allowed)

    def test_staff_augmentation_floor_tag(self):
        self.assertEqual(staff_augmentation_floor(), "augment_not_replace")


class TestContactFloor(unittest.TestCase):
    def test_below_minimum_visits_denied(self):
        r = ContactFloorReport("r1", T0, human_visits=1, visit_minutes=30,
                               companion_robot_minutes=120, prior_human_visits=3)
        v = check_contact_floor(report=r)
        self.assertFalse(v.allowed)
        self.assertIn("contact_floor_breach", v.reason)

    def test_declined_after_robot_denied(self):
        r = ContactFloorReport("r1", T0, human_visits=3, visit_minutes=60,
                               companion_robot_minutes=120, prior_human_visits=5)
        v = check_contact_floor(report=r)
        self.assertFalse(v.allowed)
        self.assertIn("contact_declined_after_robot", v.reason)

    def test_stable_contact_allowed(self):
        r = ContactFloorReport("r1", T0, human_visits=4, visit_minutes=90,
                               companion_robot_minutes=120, prior_human_visits=4)
        v = check_contact_floor(report=r)
        self.assertTrue(v.allowed)

    def test_human_contact_floor_helper(self):
        self.assertEqual(human_contact_floor(), 3)


class TestEmotionBoundary(unittest.TestCase):
    def _sig(self, impaired=False):
        return EmotionSignal("e1", "r1", "agitation", 8500, T0)

    def test_signal_only_allowed(self):
        v = check_emotion_boundary(signal=self._sig(), action=None, now=T0)
        self.assertTrue(v.allowed)

    def test_signal_driven_lock_denied(self):
        a = ConstraintAction("c1", "r1", "lock_door", driven_by_signal=True,
                             human_decided=False, decided_at=T0)
        v = check_emotion_boundary(signal=self._sig(), action=a, now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("emotion_triggered_constraint", v.reason)

    def test_human_decided_constraint_allowed(self):
        a = ConstraintAction("c2", "r1", "restrict_activity", driven_by_signal=True,
                             human_decided=True, decided_at=T0)
        v = check_emotion_boundary(signal=self._sig(), action=a, now=T0)
        self.assertTrue(v.allowed)


if __name__ == "__main__":
    unittest.main()
