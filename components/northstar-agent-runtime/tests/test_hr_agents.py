"""Tests for hr_agents (one-hundred-forty-first batch)."""

import unittest

from hr_agents import (
    DENY_BANNED_PROXY_FEATURE,
    AuditRegistry,
    AuthorityRegistry,
    CountersignRegistry,
    HrAgentsError,
    LayoffNoticeRegistry,
    RepurposeRegistry,
    ScoringDisclosureRegistry,
    VendorPinRegistry,
    audit_receipt,
    emotion_inference_ban,
    human_final_gate,
    input_bias_inheritance,
    issue_audit_receipt,
    issue_homophily_probe,
    issue_human_countersign,
    issue_layoff_notice,
    issue_repurpose_notice,
    issue_scoring_disclosure,
    issue_vendor_pin,
    layoff_ai_disclosure,
    model_homophily_probe,
    secret_scoring_probe,
    surveillance_purpose_receipt,
    vendor_agent_pin,
)


def _sec(tag):
    return (b"hr-test-" + tag.encode() + b"0" * 32)[:32]


AUTH = _sec("authority")
AUDITOR = _sec("auditor")
VENDOR = _sec("vendor")
EMPLOYER = _sec("employer")
OTHER = _sec("other")

from ed25519 import public_key as _pub  # noqa: E402

AUTH_PUB = _pub(AUTH)
AUDITOR_PUB = _pub(AUDITOR)
VENDOR_PUB = _pub(VENDOR)
EMPLOYER_PUB = _pub(EMPLOYER)
T0 = 1_800_000_000
HEX = "ab" * 32
HEX2 = "cd" * 32
HEX3 = "ef" * 32


def _auth():
    reg = AuthorityRegistry()
    reg.register("labor-board", AUTH_PUB)
    reg.register("third-party-auditor", AUDITOR_PUB)
    reg.register("hr-vendor", VENDOR_PUB)
    reg.register("employer-co", EMPLOYER_PUB)
    return reg


def _audit(vendor_id="hr-vendor", auditor_id="third-party-auditor",
           auditor_secret=AUDITOR, model_digest=HEX, features_used=()):
    return issue_audit_receipt(
        audit_id="audit-1", model_digest=model_digest,
        vendor_id=vendor_id, auditor_id=auditor_id,
        issued_at=T0, valid_until=T0 + 86400 * 90,
        banned_features_checked=("zip_code",),
        features_used=features_used,
        auditor_secret=auditor_secret,
    )


class AuditTest(unittest.TestCase):
    def test_independent_audit_allows(self):
        audits = AuditRegistry(_auth())
        audits.record(_audit())
        v = audit_receipt(audits, model_digest=HEX, checked_at=T0 + 10)
        self.assertTrue(v.allowed)
        self.assertIsNone(v.deny_code)

    def test_self_audit_refused_at_issuance(self):
        with self.assertRaises(HrAgentsError):
            issue_audit_receipt(
                audit_id="a", model_digest=HEX, vendor_id="v",
                auditor_id="v", issued_at=T0, valid_until=T0 + 10,
                auditor_secret=AUDITOR,
            )

    def test_unknown_model_denies(self):
        audits = AuditRegistry(_auth())
        v = audit_receipt(audits, model_digest=HEX2, checked_at=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "hr:audit_unknown")

    def test_expired_audit_denies(self):
        audits = AuditRegistry(_auth())
        audits.record(_audit())
        v = audit_receipt(audits, model_digest=HEX, checked_at=T0 + 86400 * 91)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "hr:audit_expired")

    def test_banned_proxy_feature_refused_at_issuance(self):
        with self.assertRaises(HrAgentsError) as cm:
            _audit(features_used=("zip_code", "tenure"))
        self.assertIn(DENY_BANNED_PROXY_FEATURE, str(cm.exception))


class SecretScoringTest(unittest.TestCase):
    def _disclosure(self, secret=VENDOR, disclosed_at=T0):
        return issue_scoring_disclosure(
            disclosure_id="d-1", scoring_system_id="eightfold-like",
            subject_id="worker-1", disclosed_at=disclosed_at,
            access_path="https://portal.example/access",
            dispute_path="https://portal.example/dispute",
            issuer_secret=secret,
        )

    def test_disclosed_scoring_allows(self):
        reg = ScoringDisclosureRegistry()
        reg.record(self._disclosure())
        v = secret_scoring_probe(
            reg, _auth(), scoring_system_id="eightfold-like",
            subject_id="worker-1", scored_at=T0 + 5, issuer_id="hr-vendor")
        self.assertTrue(v.allowed)

    def test_undisclosed_scoring_denies(self):
        reg = ScoringDisclosureRegistry()
        v = secret_scoring_probe(
            reg, _auth(), scoring_system_id="eightfold-like",
            subject_id="worker-1", scored_at=T0 + 5, issuer_id="hr-vendor")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "hr:secret_scoring")

    def test_disclosure_after_scoring_denies(self):
        reg = ScoringDisclosureRegistry()
        reg.record(self._disclosure(disclosed_at=T0 + 100))
        v = secret_scoring_probe(
            reg, _auth(), scoring_system_id="eightfold-like",
            subject_id="worker-1", scored_at=T0 + 5, issuer_id="hr-vendor")
        self.assertEqual(v.deny_code, "hr:secret_scoring")


class HumanFinalTest(unittest.TestCase):
    def _sign(self, minutes=30):
        return issue_human_countersign(
            decision_id="dec-1", decision_kind="firing",
            evidence_digest=HEX, reviewer_name="M. Reviewer",
            review_minutes=minutes, review_notes_digest=HEX2,
            countersigned_at=T0, reviewer_secret=AUTH,
        )

    def test_substantive_countersign_allows(self):
        reg = CountersignRegistry()
        reg.record(self._sign())
        v = human_final_gate(
            reg, _auth(), decision_id="dec-1", decision_kind="firing",
            evidence_digest=HEX, ai_involved=True, decided_at=T0 + 10,
            reviewer_id="labor-board")
        self.assertTrue(v.allowed)

    def test_no_countersign_denies(self):
        reg = CountersignRegistry()
        v = human_final_gate(
            reg, _auth(), decision_id="dec-9", decision_kind="firing",
            evidence_digest=HEX, ai_involved=True, decided_at=T0,
            reviewer_id="labor-board")
        self.assertEqual(v.deny_code, "hr:no_human_countersign")

    def test_rubber_stamp_denies(self):
        reg = CountersignRegistry()
        reg.record(self._sign(minutes=2))
        v = human_final_gate(
            reg, _auth(), decision_id="dec-1", decision_kind="firing",
            evidence_digest=HEX, ai_involved=True, decided_at=T0 + 10,
            reviewer_id="labor-board")
        self.assertEqual(v.deny_code, "hr:rubber_stamp")

    def test_no_ai_involvement_needs_nothing(self):
        reg = CountersignRegistry()
        v = human_final_gate(
            reg, _auth(), decision_id="dec-x", decision_kind="promotion",
            evidence_digest=HEX, ai_involved=False, decided_at=T0,
            reviewer_id="labor-board")
        self.assertTrue(v.allowed)


class EmotionBanTest(unittest.TestCase):
    def test_ai_biometric_emotion_refused(self):
        v = emotion_inference_ban(
            use_kind="emotion_prediction", uses_ai=True, uses_biometrics=True)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "hr:emotion_inference")

    def test_non_biometric_sentiment_allowed(self):
        v = emotion_inference_ban(
            use_kind="sentiment_scoring", uses_ai=True, uses_biometrics=False)
        self.assertTrue(v.allowed)

    def test_human_only_allowed(self):
        v = emotion_inference_ban(
            use_kind="engagement_inference", uses_ai=False, uses_biometrics=True)
        self.assertTrue(v.allowed)


class RepurposeTest(unittest.TestCase):
    def _notice(self):
        return issue_repurpose_notice(
            notice_id="n-1", monitoring_source_digest=HEX,
            new_purpose="productivity_scoring", notice_given_at=T0,
            appeal_receipt_digest=HEX2, issuer_secret=EMPLOYER,
        )

    def test_noticed_repurpose_allows(self):
        reg = RepurposeRegistry()
        reg.record(self._notice())
        v = surveillance_purpose_receipt(
            reg, _auth(), monitoring_source_digest=HEX,
            employment_use=True, used_at=T0 + 100, issuer_id="employer-co")
        self.assertTrue(v.allowed)

    def test_unnoticed_repurpose_denies(self):
        reg = RepurposeRegistry()
        v = surveillance_purpose_receipt(
            reg, _auth(), monitoring_source_digest=HEX,
            employment_use=True, used_at=T0, issuer_id="employer-co")
        self.assertEqual(v.deny_code, "hr:surveillance_repurpose")

    def test_non_employment_use_needs_nothing(self):
        reg = RepurposeRegistry()
        v = surveillance_purpose_receipt(
            reg, _auth(), monitoring_source_digest=HEX,
            employment_use=False, used_at=T0, issuer_id="employer-co")
        self.assertTrue(v.allowed)


class HomophilyTest(unittest.TestCase):
    def _probe(self, ai_passes=30, human_passes=30):
        return issue_homophily_probe(
            probe_id="p-1", model_digest=HEX,
            ai_written_passes=ai_passes, ai_written_total=100,
            human_written_passes=human_passes, human_written_total=100,
            measured_at=T0, expires_at=T0 + 86400 * 30,
            issuer_secret=AUDITOR,
        )

    def test_balanced_probe_allows(self):
        v = model_homophily_probe(
            self._probe(), _auth(), issuer_id="third-party-auditor",
            checked_at=T0 + 10)
        self.assertTrue(v.allowed)
        self.assertAlmostEqual(v.pass_rate_ratio, 1.0)

    def test_skewed_probe_quarantines(self):
        v = model_homophily_probe(
            self._probe(ai_passes=60, human_passes=30), _auth(),
            issuer_id="third-party-auditor", checked_at=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "hr:homophily_audit")
        self.assertAlmostEqual(v.pass_rate_ratio, 2.0)


class LayoffTest(unittest.TestCase):
    def test_noticed_layoff_allows(self):
        reg = LayoffNoticeRegistry()
        reg.record(issue_layoff_notice(
            notice_id="ln-1", layoff_id="lay-1",
            ai_involvement_digest=HEX, written_notice_digest=HEX2,
            evidence_chain_digest=HEX3, issued_at=T0,
            issuer_secret=EMPLOYER))
        v = layoff_ai_disclosure(
            reg, _auth(), layoff_id="lay-1", ai_involved=True,
            issuer_id="employer-co")
        self.assertTrue(v.allowed)

    def test_unnoticed_layoff_denies(self):
        reg = LayoffNoticeRegistry()
        v = layoff_ai_disclosure(
            reg, _auth(), layoff_id="lay-9", ai_involved=True,
            issuer_id="employer-co")
        self.assertEqual(v.deny_code, "hr:no_layoff_notice")

    def test_non_ai_layoff_needs_nothing(self):
        reg = LayoffNoticeRegistry()
        v = layoff_ai_disclosure(
            reg, _auth(), layoff_id="lay-x", ai_involved=False,
            issuer_id="employer-co")
        self.assertTrue(v.allowed)


class InputBiasTest(unittest.TestCase):
    def test_audited_source_allows_downstream(self):
        audits = AuditRegistry(_auth())
        audits.record(_audit())
        v = input_bias_inheritance(
            audits, evaluation_output_digest=HEX2, source_model_digest=HEX,
            used_for="promotion", checked_at=T0 + 10)
        self.assertTrue(v.allowed)

    def test_unaudited_source_taints_downstream(self):
        audits = AuditRegistry(_auth())
        v = input_bias_inheritance(
            audits, evaluation_output_digest=HEX2, source_model_digest=HEX,
            used_for="layoff", checked_at=T0)
        self.assertEqual(v.deny_code, "hr:tainted_input")


class VendorPinTest(unittest.TestCase):
    def test_pinned_vendor_allows(self):
        reg = VendorPinRegistry()
        reg.record(issue_vendor_pin(
            pin_id="vp-1", vendor_id="workday-like", employer_id="employer-co",
            scope="screening", issued_at=T0, issuer_secret=EMPLOYER))
        v = vendor_agent_pin(
            reg, _auth(), vendor_id="workday-like",
            employer_id="employer-co", issuer_id="employer-co")
        self.assertTrue(v.allowed)

    def test_unpinned_vendor_denies(self):
        reg = VendorPinRegistry()
        v = vendor_agent_pin(
            reg, _auth(), vendor_id="workday-like",
            employer_id="employer-co", issuer_id="employer-co")
        self.assertEqual(v.deny_code, "hr:unpinned_vendor")


if __name__ == "__main__":
    unittest.main()
