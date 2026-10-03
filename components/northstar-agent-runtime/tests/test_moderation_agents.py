"""Tests for the one-hundred-fiftieth batch: content moderation discipline."""

import unittest

import moderation_agents as ma
from moderation_agents import ModerationError


AUTH = b"moderation-bench-auth-0000000001"   # 32 bytes
assert len(AUTH) == 32
T0 = 1_800_000_000
H64 = "ab" * 32


def sor(**kw):
    args = dict(
        receipt_id="sor-1",
        content_id="post-1",
        decision_kind="removal",
        reason_code="harassment",
        issued_by="mod-team",
        authority_secret=AUTH,
        issued_at=T0,
        expires_at=T0 + 86400,
        decision_digest=H64,
    )
    args.update(kw)
    return ma.statement_of_reasons(**args)


def lrr(**kw):
    args = dict(
        receipt_id="lrr-1",
        content_id="post-1",
        country_code="DE",
        legal_basis="NetzDG s.3",
        restricted_at=T0,
        expires_at=T0 + 86400,
        authority_secret=AUTH,
    )
    args.update(kw)
    return ma.legal_restriction_receipt(**args)


def alr(**kw):
    args = dict(
        receipt_id="alr-1",
        content_digest=H64,
        ai_generated=True,
        generator_id="gen-1",
        labeled_at=T0,
        labeler_secret=AUTH,
    )
    args.update(kw)
    return ma.aigc_label_receipt(**args)


def aar(**kw):
    args = dict(
        audit_id="aa-1",
        recommender_id="rec-1",
        completed_at=T0,
        findings_digest=H64,
        auditor_secret=AUTH,
    )
    args.update(kw)
    return ma.amplification_audit_receipt(**args)


class StatementOfReasonsTests(unittest.TestCase):
    def test_round_trip_allows(self):
        v = ma.check_statement_of_reasons(sor(), now=T0, content_id="post-1", decision_digest=H64)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, ma.CLASS_AUTHORITATIVE)

    def test_shadowban_needs_reason_too(self):
        r = sor(decision_kind="visibility_reduction")
        v = ma.check_statement_of_reasons(r, now=T0, content_id="post-1", decision_digest=H64)
        self.assertTrue(v.allowed)

    def test_missing_receipt_denies(self):
        v = ma.check_statement_of_reasons(None, now=T0, content_id="post-1", decision_digest=H64)
        self.assertFalse(v.allowed)
        self.assertIn("moderation.no_statement_of_reasons", v.reason)

    def test_expired_receipt_denies(self):
        r = sor(issued_at=T0 - 100000, expires_at=T0 - 10)
        v = ma.check_statement_of_reasons(r, now=T0, content_id="post-1", decision_digest=H64)
        self.assertFalse(v.allowed)

    def test_digest_mismatch_denies(self):
        r = sor()
        v = ma.check_statement_of_reasons(r, now=T0, content_id="post-1", decision_digest="cd" * 32)
        self.assertFalse(v.allowed)


class OverremovalProbeTests(unittest.TestCase):
    def test_high_restoration_rate_denies(self):
        reg = ma.OverremovalRegistry("r1", decisions=1000, appeals=200, appeal_restored=30, declared_at=T0)
        v = ma.overremoval_probe(reg)
        self.assertFalse(v.allowed)
        self.assertIn("moderation.overremoval_audit", v.reason)

    def test_within_tolerance_allows(self):
        reg = ma.OverremovalRegistry("r2", decisions=1000, appeals=200, appeal_restored=5, declared_at=T0)
        v = ma.overremoval_probe(reg)
        self.assertTrue(v.allowed)

    def test_no_appeals_allows(self):
        reg = ma.OverremovalRegistry("r3", decisions=1000, appeals=0, appeal_restored=0, declared_at=T0)
        v = ma.overremoval_probe(reg)
        self.assertTrue(v.allowed)

    def test_inconsistent_counts_raise(self):
        with self.assertRaises(ModerationError):
            ma.overremoval_probe(ma.OverremovalRegistry("r4", decisions=10, appeals=20, appeal_restored=0, declared_at=T0))


class DialectParityTests(unittest.TestCase):
    def _report(self, fp_counts):
        return ma.DialectParityReport("dp-1", "msa", fp_counts, T0)

    def test_systematic_fp_disparity_denies(self):
        rep = self._report((("msa", 5, 100), ("egyptian", 40, 100)))
        v = ma.check_dialect_parity(rep)
        self.assertFalse(v.allowed)
        self.assertIn("moderation.dialect_bias", v.reason)

    def test_parity_allows(self):
        rep = self._report((("msa", 5, 100), ("egyptian", 6, 100)))
        v = ma.check_dialect_parity(rep)
        self.assertTrue(v.allowed)

    def test_duplicate_dialect_raises(self):
        with self.assertRaises(ModerationError):
            ma.check_dialect_parity(self._report((("msa", 5, 100), ("msa", 6, 100))))


class AutomationCeilingTests(unittest.TestCase):
    def test_tier1_auto_allows(self):
        v = ma.check_automation_ceiling(severity=ma.SEVERITY_TIER_1, decision_mode=ma.MODE_FULLY_AUTOMATED)
        self.assertTrue(v.allowed)

    def test_lower_tier_auto_denies(self):
        v = ma.check_automation_ceiling(severity=ma.SEVERITY_TIER_3, decision_mode=ma.MODE_FULLY_AUTOMATED)
        self.assertFalse(v.allowed)
        self.assertIn("moderation.auto_overreach", v.reason)

    def test_lower_tier_human_review_allows(self):
        v = ma.check_automation_ceiling(severity=ma.SEVERITY_TIER_3, decision_mode=ma.MODE_HUMAN_REVIEW)
        self.assertTrue(v.allowed)


class NonProfilingTests(unittest.TestCase):
    def test_absent_denies(self):
        cfg = ma.RecommenderConfig("rec-1", False, "", T0)
        v = ma.check_non_profiling_option(cfg)
        self.assertFalse(v.allowed)
        self.assertIn("moderation.no_non_profiling_option", v.reason)

    def test_present_allows(self):
        cfg = ma.RecommenderConfig("rec-1", True, "np-feed", T0)
        v = ma.check_non_profiling_option(cfg)
        self.assertTrue(v.allowed)


class LegalRestrictionTests(unittest.TestCase):
    def test_round_trip_allows(self):
        v = ma.check_legal_restriction(lrr(), now=T0, content_id="post-1")
        self.assertTrue(v.allowed)

    def test_missing_receipt_denies(self):
        v = ma.check_legal_restriction(None, now=T0, content_id="post-1")
        self.assertFalse(v.allowed)
        self.assertIn("moderation.undisclosed_restriction", v.reason)


class WhyThisContentTests(unittest.TestCase):
    def test_matching_binding_allows(self):
        b = ma.why_this_content(decision_digest=H64, explanation="harassment: targeted slur")
        v = ma.check_why_this_content(b, decision_digest=H64, explanation="harassment: targeted slur")
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, ma.CLASS_AUTHORITATIVE)

    def test_missing_binding_degrades(self):
        v = ma.check_why_this_content(None, decision_digest=H64, explanation="harassment")
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, ma.CLASS_NON_AUTHORITATIVE)

    def test_mismatched_binding_degrades(self):
        b = ma.why_this_content(decision_digest=H64, explanation="spam")
        v = ma.check_why_this_content(b, decision_digest=H64, explanation="harassment")
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, ma.CLASS_NON_AUTHORITATIVE)


class FactcheckTests(unittest.TestCase):
    def test_substitution_denies(self):
        p = ma.FactcheckProgram("p1", True, False, True, True, T0)
        v = ma.check_factcheck_non_substitution(p)
        self.assertFalse(v.allowed)
        self.assertIn("moderation.factcheck_substitution", v.reason)

    def test_supplement_allows(self):
        p = ma.FactcheckProgram("p2", True, True, True, False, T0)
        v = ma.check_factcheck_non_substitution(p)
        self.assertTrue(v.allowed)


class AIGCLabelTests(unittest.TestCase):
    def test_unlabeled_aigc_denies(self):
        v = ma.check_aigc_label(None, content_digest=H64, ai_generated=True)
        self.assertFalse(v.allowed)
        self.assertIn("moderation.unlabeled_aigc", v.reason)

    def test_labeled_aigc_allows(self):
        v = ma.check_aigc_label(alr(), content_digest=H64, ai_generated=True)
        self.assertTrue(v.allowed)

    def test_non_ai_allows_without_label(self):
        v = ma.check_aigc_label(None, content_digest=H64, ai_generated=False)
        self.assertTrue(v.allowed)


class AmplificationClockTests(unittest.TestCase):
    def test_fresh_audit_allows(self):
        v = ma.check_amplification_clock(aar(completed_at=T0), now=T0)
        self.assertTrue(v.allowed)

    def test_overdue_audit_denies(self):
        v = ma.check_amplification_clock(aar(completed_at=T0), now=T0 + ma.AMPLIFICATION_AUDIT_WINDOW_S + 1)
        self.assertFalse(v.allowed)
        self.assertIn("moderation.amplification_audit_overdue", v.reason)

    def test_no_audit_denies(self):
        v = ma.check_amplification_clock(None, now=T0)
        self.assertFalse(v.allowed)


if __name__ == "__main__":
    unittest.main()
