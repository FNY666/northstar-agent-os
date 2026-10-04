"""Tests for proptech_agents.py (one-hundred-fifty-ninth batch)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ed25519 import public_key

import proptech_agents as p

T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
ZERO64 = "00" * 32
SEC = b"pt-test-" + b"0" * 24  # 32 bytes
assert len(SEC) == 32


def _authorities():
    auth = p.AuthorityRegistry()
    auth.register("pt-op", public_key(SEC).hex())
    return auth


def _regs():
    auth = _authorities()
    return {
        "criteria": p.ScreeningCriteriaRegistry(auth),
        "decisions": p.ScreeningDecisionRegistry(auth),
        "adverse": p.AdverseActionRegistry(auth),
        "impact": p.DisparateImpactAuditRegistry(auth),
        "pricing": p.PricingDataRegistry(auth),
        "juris": p.RentJurisdictionRegistry(auth),
        "broker": p.BrokerLiabilityRegistry(auth),
        "valuations": p.ValuationRegistry(auth),
        "benchmarks": p.BenchmarkReferenceRegistry(auth),
        "ads": p.AdDeliveryAuditRegistry(auth),
    }


def _crit(r, published_at=T0):
    return r["criteria"].issue(
        "crit-1", "owner-1", HEX64, published_at, "pt-op", SEC)


def _dec(r, receipt_id="dec-1", voucher=False, score=False,
         recommendation="decline", decider="human", criteria_id="crit-1",
         decided_at=T0 + 10):
    return r["decisions"].issue(
        receipt_id, "app-1", voucher, score, recommendation, decider,
        criteria_id, decided_at, "pt-op", SEC)


class ScreeningScoreSilencingTest(unittest.TestCase):
    def test_voucher_score_shown_denies(self):
        r = _regs(); _crit(r)
        _dec(r, voucher=True, score=True)
        v = p.screening_score_silencing(r["decisions"], "dec-1")
        self.assertFalse(v.allowed)
        self.assertIn("proptech:voucher_score_shown", v.reason)

    def test_voucher_recommendation_denies(self):
        r = _regs(); _crit(r)
        _dec(r, voucher=True, score=False, recommendation="decline")
        v = p.screening_score_silencing(r["decisions"], "dec-1")
        self.assertFalse(v.allowed)
        self.assertIn("proptech:voucher_score_shown", v.reason)

    def test_voucher_silent_allows(self):
        r = _regs(); _crit(r)
        _dec(r, voucher=True, score=False, recommendation="no_recommendation")
        v = p.screening_score_silencing(r["decisions"], "dec-1")
        self.assertTrue(v.allowed)

    def test_non_voucher_not_silenced(self):
        r = _regs(); _crit(r)
        _dec(r, voucher=False, score=True)
        v = p.screening_score_silencing(r["decisions"], "dec-1")
        self.assertTrue(v.allowed)

    def test_missing_decision_denies(self):
        r = _regs()
        v = p.screening_score_silencing(r["decisions"], "ghost")
        self.assertFalse(v.allowed)
        self.assertIn("proptech:no_screening_decision", v.reason)


class CriteriaPinTest(unittest.TestCase):
    def test_pinned_before_decision_allows(self):
        r = _regs()
        _crit(r, published_at=T0)
        _dec(r, decided_at=T0 + 10)
        v = p.screening_criteria_pin(r["criteria"], r["decisions"], "dec-1")
        self.assertTrue(v.allowed)

    def test_published_after_denies(self):
        r = _regs()
        _crit(r, published_at=T0 + 100)
        _dec(r, decided_at=T0 + 10)
        v = p.screening_criteria_pin(r["criteria"], r["decisions"], "dec-1")
        self.assertFalse(v.allowed)
        self.assertIn("proptech.unpinned_criteria", v.reason)

    def test_no_criteria_denies(self):
        r = _regs()
        _dec(r, criteria_id="crit-missing")
        v = p.screening_criteria_pin(r["criteria"], r["decisions"], "dec-1")
        self.assertFalse(v.allowed)
        self.assertIn("proptech.unpinned_criteria", v.reason)


class HumanFinalTest(unittest.TestCase):
    def test_ai_specific_decision_denies(self):
        r = _regs(); _crit(r)
        _dec(r, decider="ai", recommendation="decline")
        v = p.human_final_gate_screening(r["decisions"], "dec-1")
        self.assertFalse(v.allowed)
        self.assertIn("proptech:ai_specific_decision", v.reason)

    def test_ai_draft_only_allows(self):
        r = _regs(); _crit(r)
        _dec(r, decider="ai", recommendation="no_recommendation")
        v = p.human_final_gate_screening(r["decisions"], "dec-1")
        self.assertTrue(v.allowed)

    def test_human_decision_allows(self):
        r = _regs(); _crit(r)
        _dec(r, decider="human", recommendation="decline")
        v = p.human_final_gate_screening(r["decisions"], "dec-1")
        self.assertTrue(v.allowed)


class AdverseActionTest(unittest.TestCase):
    def _aa(self, r, reasons):
        return r["adverse"].issue(
            "aa-1", "app-1", "dec-1", reasons, HEX64_B,
            "appeals@example.com", T0 + 20, "pt-op", SEC)

    def test_denial_with_specific_reasons_allows(self):
        r = _regs(); _crit(r)
        _dec(r, recommendation="decline")
        self._aa(r, ["eviction within 3 years", "insufficient verifiable income"])
        v = p.adverse_action_receipt(r["adverse"], r["decisions"], "dec-1")
        self.assertTrue(v.allowed)

    def test_vague_reason_denies(self):
        r = _regs(); _crit(r)
        _dec(r, recommendation="decline")
        self._aa(r, ["ai score"])
        v = p.adverse_action_receipt(r["adverse"], r["decisions"], "dec-1")
        self.assertFalse(v.allowed)
        self.assertIn("proptech:vague_adverse_reason", v.reason)

    def test_denial_without_receipt_denies(self):
        r = _regs(); _crit(r)
        _dec(r, recommendation="decline")
        v = p.adverse_action_receipt(r["adverse"], r["decisions"], "dec-1")
        self.assertFalse(v.allowed)
        self.assertIn("proptech:no_adverse_action", v.reason)

    def test_accept_needs_no_adverse_action(self):
        r = _regs(); _crit(r)
        _dec(r, recommendation="accept")
        v = p.adverse_action_receipt(r["adverse"], r["decisions"], "dec-1")
        self.assertTrue(v.allowed)


class ImpactAuditTest(unittest.TestCase):
    def test_clean_audit_allows(self):
        r = _regs()
        r["impact"].issue("imp-1", "model-1", 0.92, False, T0, "pt-op", SEC)
        v = p.disparate_impact_audit_receipt(r["impact"], "model-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_impact_finding_withdraws_model(self):
        r = _regs()
        r["impact"].issue("imp-1", "model-1", 0.61, True, T0, "pt-op", SEC)
        v = p.disparate_impact_audit_receipt(r["impact"], "model-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:disparate_impact", v.reason)

    def test_no_audit_denies(self):
        r = _regs()
        v = p.disparate_impact_audit_receipt(r["impact"], "ghost", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:no_impact_audit", v.reason)

    def test_stale_audit_denies(self):
        r = _regs()
        r["impact"].issue("imp-1", "model-1", 0.92, False, T0, "pt-op", SEC)
        v = p.disparate_impact_audit_receipt(
            r["impact"], "model-1", T0 + p.RECEIPT_MAX_AGE_S + 1)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:no_impact_audit", v.reason)


class PricingFirewallTest(unittest.TestCase):
    def _pd(self, r, cutoff, nonpublic, freshest):
        return r["pricing"].issue(
            "pd-1", "pricing-1", cutoff, nonpublic, freshest, T0, "pt-op", SEC)

    def test_old_data_allows(self):
        r = _regs()
        self._pd(r, T0 - p.PRICING_DATA_MIN_AGE_S - 100, False, 0)
        v = p.pricing_data_firewall(r["pricing"], "pricing-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_fresh_data_denies(self):
        r = _regs()
        self._pd(r, T0 - 100, False, 0)
        v = p.pricing_data_firewall(r["pricing"], "pricing-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech.stale_data_violation", v.reason)

    def test_fresh_competitor_data_denies(self):
        r = _regs()
        self._pd(r, T0 - p.PRICING_DATA_MIN_AGE_S - 100, True, T0 - 50)
        v = p.pricing_data_firewall(r["pricing"], "pricing-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech.stale_data_violation", v.reason)

    def test_no_declaration_denies(self):
        r = _regs()
        v = p.pricing_data_firewall(r["pricing"], "ghost", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:no_pricing_declaration", v.reason)

    def test_competitor_nonpublic_triggers_antitrust(self):
        r = _regs()
        self._pd(r, T0 - p.PRICING_DATA_MIN_AGE_S - 100, True,
                 T0 - p.PRICING_DATA_MIN_AGE_S - 50)
        v = p.competitor_data_probe(r["pricing"], "pricing-1")
        self.assertFalse(v.allowed)
        self.assertIn("proptech:collusion_input", v.reason)

    def test_clean_probe_allows(self):
        r = _regs()
        self._pd(r, T0 - p.PRICING_DATA_MIN_AGE_S - 100, False, 0)
        v = p.competitor_data_probe(r["pricing"], "pricing-1")
        self.assertTrue(v.allowed)


class JurisdictionTest(unittest.TestCase):
    def test_matrix_allows(self):
        r = _regs()
        r["juris"].issue("jur-1", "ny", HEX64, False, T0, "pt-op", SEC)
        v = p.rent_jurisdiction_matrix(r["juris"], "ny", True, T0 + 10)
        self.assertTrue(v.allowed)

    def test_ban_denies(self):
        r = _regs()
        r["juris"].issue("jur-1", "ny", HEX64, True, T0, "pt-op", SEC)
        v = p.rent_jurisdiction_matrix(r["juris"], "ny", True, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:jurisdiction_ban", v.reason)

    def test_no_pin_denies(self):
        r = _regs()
        v = p.rent_jurisdiction_matrix(r["juris"], "co", True, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:no_jurisdiction_pin", v.reason)


class AdDeliveryTest(unittest.TestCase):
    def test_no_skew_allows(self):
        r = _regs()
        r["ads"].issue("ad-1", "camp-1", HEX64, False, T0, "pt-op", SEC)
        v = p.target_ad_delivery_audit(r["ads"], "camp-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_skew_halts(self):
        r = _regs()
        r["ads"].issue("ad-1", "camp-1", HEX64, True, T0, "pt-op", SEC)
        v = p.target_ad_delivery_audit(r["ads"], "camp-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:ad_delivery_skew", v.reason)

    def test_no_audit_denies(self):
        r = _regs()
        v = p.target_ad_delivery_audit(r["ads"], "ghost", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:no_ad_audit", v.reason)


class BrokerLiabilityTest(unittest.TestCase):
    def test_anchor_allows(self):
        r = _regs()
        r["broker"].issue("bl-1", "txn-1", "broker-7",
                          public_key(SEC).hex(), T0, "pt-op", SEC)
        v = p.broker_liability_pin(r["broker"], "txn-1", "broker-7")
        self.assertTrue(v.allowed)

    def test_no_anchor_denies(self):
        r = _regs()
        v = p.broker_liability_pin(r["broker"], "txn-ghost", "broker-7")
        self.assertFalse(v.allowed)
        self.assertIn("proptech.no_liability_anchor", v.reason)

    def test_mismatch_denies(self):
        r = _regs()
        r["broker"].issue("bl-1", "txn-1", "broker-7",
                          public_key(SEC).hex(), T0, "pt-op", SEC)
        v = p.broker_liability_pin(r["broker"], "txn-1", "broker-9")
        self.assertFalse(v.allowed)
        self.assertIn("proptech:liability_mismatch", v.reason)


class ValuationTest(unittest.TestCase):
    def test_high_confidence_allows(self):
        r = _regs()
        r["valuations"].issue("val-1", "prop-1", 50000000, 0.85, "ai",
                              T0, "pt-op", SEC)
        v = p.valuation_confidence_floor(r["valuations"], "val-1")
        self.assertTrue(v.allowed)

    def test_low_confidence_denies(self):
        r = _regs()
        r["valuations"].issue("val-1", "prop-1", 50000000, 0.42, "ai",
                              T0, "pt-op", SEC)
        v = p.valuation_confidence_floor(r["valuations"], "val-1")
        self.assertFalse(v.allowed)
        self.assertIn("proptech:low_confidence_valuation", v.reason)

    def test_human_valuer_exempt(self):
        r = _regs()
        r["valuations"].issue("val-1", "prop-1", 50000000, 0.30, "human",
                              T0, "pt-op", SEC)
        v = p.valuation_confidence_floor(r["valuations"], "val-1")
        self.assertTrue(v.allowed)


class BenchmarkTest(unittest.TestCase):
    def test_reference_allows(self):
        r = _regs()
        r["benchmarks"].issue("bm-1", "dubai-marina", HEX64, "dld-smart-index",
                              400, ZERO64, T0, "pt-op", SEC)
        v = p.public_benchmark_reference(r["benchmarks"], "dubai-marina", T0 + 10)
        self.assertTrue(v.allowed)

    def test_no_benchmark_denies(self):
        r = _regs()
        v = p.public_benchmark_reference(r["benchmarks"], "ghost", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:no_benchmark", v.reason)

    def test_unjustified_deviation_denies(self):
        r = _regs()
        r["benchmarks"].issue("bm-1", "dubai-marina", HEX64, "dld-smart-index",
                              2500, ZERO64, T0, "pt-op", SEC)
        v = p.public_benchmark_reference(r["benchmarks"], "dubai-marina", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("proptech:unjustified_deviation", v.reason)

    def test_justified_deviation_allows(self):
        r = _regs()
        r["benchmarks"].issue("bm-1", "dubai-marina", HEX64, "dld-smart-index",
                              2500, HEX64_B, T0, "pt-op", SEC)
        v = p.public_benchmark_reference(r["benchmarks"], "dubai-marina", T0 + 10)
        self.assertTrue(v.allowed)


class StructuralTest(unittest.TestCase):
    def test_chain_break_detected(self):
        r = _regs()
        rec = _crit(r)
        fields = {f.name: getattr(rec, f.name)
                  for f in rec.__dataclass_fields__.values()}
        fields["signature_hex"] = "ff" * 64
        r["criteria"].log[0] = rec.__class__(**fields)
        with self.assertRaises(p.ProptechError):
            p._check_chain(r["criteria"].log, "screening_criteria")

    def test_unknown_authority_rejected(self):
        r = _regs()
        with self.assertRaises(p.ProptechError):
            r["criteria"].issue("crit-x", "owner-1", HEX64, T0, "ghost", SEC)

    def test_vague_reasons_catalog(self):
        self.assertIn("model output", p.VAGUE_REASONS)
        self.assertIn("ai score", p.VAGUE_REASONS)


if __name__ == "__main__":
    unittest.main()
