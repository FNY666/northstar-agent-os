"""Tests for retail_agents.py (one-hundred-sixty-fourth batch)."""

import hashlib
import sys
import unittest

sys.path.insert(0, ".")  # run from components/northstar-agent-runtime

import ed25519
from retail_agents import (
    AuthorityRegistry,
    CheckoutScreening,
    ClaimEvidenceRegistry,
    DataFlowDeclaration,
    ESLChangeLog,
    PriceDisclosureRegistry,
    PriceDisclosureReceipt,
    PricingFeatureAudit,
    QuotaDisclosure,
    QuoteBlindnessEvidence,
    RetailError,
    ShashaRegistry,
    MerchantRuleRegistry,
    UpsellRegistry,
    WearableCollectionRegistry,
    agentic_quote_blindness,
    assistant_fact_gate,
    dark_pattern_screen,
    esl_change_log,
    merchant_rule_disclosure,
    no_protected_class_pricing,
    personalized_price_disclosure,
    product_not_person_pin,
    quota_transparency,
    shasha_receipt,
    upsell_transparency,
    wearable_surveillance_budget,
)

SEC = b"rt-bench-auth-" + b"1" * 18  # 32 bytes
assert len(SEC) == 32
PUB = ed25519.public_key(SEC).hex()
T0 = 1_800_000_000
HEX64 = "ab" * 32


def _auth() -> AuthorityRegistry:
    reg = AuthorityRegistry()
    reg.register("bench-rt-op", PUB)
    return reg


class PersonalizedPriceDisclosureTest(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = PriceDisclosureRegistry(self.auth)
        self.r = self.reg.issue(
            receipt_id="pd-1", merchant_id="m-1", item_id="i-1",
            personalized_price_minor=9999,
            disclosure_text="This price is set by an algorithm using your personal data.",
            shown_at=T0, authority_id="bench-rt-op", authority_secret=SEC)

    def test_allow_disclosed(self):
        v = personalized_price_disclosure(
            self.reg, "pd-1", "m-1", "i-1", 9999, T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_deny_undisclosed(self):
        v = personalized_price_disclosure(
            self.reg, "pd-missing", "m-1", "i-1", 9999, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:undisclosed_personalization", v.reason)

    def test_deny_price_mismatch(self):
        v = personalized_price_disclosure(
            self.reg, "pd-1", "m-1", "i-1", 8888, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:disclosure_price_mismatch", v.reason)


class NoProtectedClassPricingTest(unittest.TestCase):
    def test_allow_clean_features(self):
        a = PricingFeatureAudit("a-1", "eng-1",
                               ("aggregate_demand_forecast", "inventory_level"),
                               T0, "bench-rt-op")
        self.assertTrue(no_protected_class_pricing(a).allowed)

    def test_deny_proxy_features(self):
        a = PricingFeatureAudit("a-2", "eng-1",
                               ("aggregate_demand_forecast", "zip_code", "device_model"),
                               T0, "bench-rt-op")
        v = no_protected_class_pricing(a)
        self.assertFalse(v.allowed)
        self.assertIn("retail:proxy_pricing_feature", v.reason)


class ESLChangeLogTest(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.log = ESLChangeLog(self.auth)
        self.log.issue(
            entry_id="esl-1", store_id="s-1", item_id="i-1",
            old_price_minor=1000, new_price_minor=1200,
            changed_at=T0, trigger_rule="nightly_cost_index",
            authority_id="bench-rt-op", authority_secret=SEC)

    def test_allow_cart_matches_shelf(self):
        v = esl_change_log(self.log, "s-1", "i-1", 1200, T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_cart_shelf_mismatch(self):
        v = esl_change_log(self.log, "s-1", "i-1", 1000, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:cart_shelf_mismatch", v.reason)

    def test_deny_unlogged_change(self):
        v = esl_change_log(self.log, "s-1", "i-2", 1200, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:unlogged_change", v.reason)


class ProductNotPersonPinTest(unittest.TestCase):
    def test_allow_aggregate_only(self):
        d = DataFlowDeclaration("df-1", "eng-1",
                               ("aggregate_demand_forecast", "inventory_level"),
                               T0, "bench-rt-op")
        self.assertTrue(product_not_person_pin(d).allowed)

    def test_deny_personalization_crossing(self):
        d = DataFlowDeclaration("df-2", "eng-1",
                               ("aggregate_demand_forecast", "browsing_history",
                                "willingness_to_pay_score"),
                               T0, "bench-rt-op")
        v = product_not_person_pin(d)
        self.assertFalse(v.allowed)
        self.assertIn("retail:pricing_data_crossed", v.reason)


class UpsellTransparencyTest(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = UpsellRegistry(self.auth)
        self.ok = self.reg.issue(
            receipt_id="up-1", merchant_id="m-1", item_id="i-1",
            list_price_minor=10000, offered_price_minor=10900,
            reason_text="Matches your stated requirements; higher efficiency rating.",
            alternatives=("i-2", "i-3"), recommended_at=T0,
            authority_id="bench-rt-op", authority_secret=SEC)

    def test_allow_bound_reason_and_alternatives(self):
        v = upsell_transparency(self.reg, "up-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_missing_receipt(self):
        v = upsell_transparency(self.reg, "up-missing", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:opaque_upsell", v.reason)

    def test_deny_premium_without_alternatives(self):
        self.reg.issue(
            receipt_id="up-2", merchant_id="m-1", item_id="i-4",
            list_price_minor=10000, offered_price_minor=12500,
            reason_text="Premium choice.", alternatives=(),
            recommended_at=T0, authority_id="bench-rt-op", authority_secret=SEC)
        v = upsell_transparency(self.reg, "up-2", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:opaque_upsell", v.reason)


class AgenticQuoteBlindnessTest(unittest.TestCase):
    def test_allow_blind_quote(self):
        e = QuoteBlindnessEvidence("q-1", "agent-a", "agent-b",
                                   ("item_spec_digest", "delivery_window"),
                                   T0, "bench-rt-op")
        self.assertTrue(agentic_quote_blindness(e).allowed)

    def test_deny_wtp_scored(self):
        e = QuoteBlindnessEvidence("q-2", "agent-a", "agent-b",
                                   ("wallet_balance", "counterparty_graph"),
                                   T0, "bench-rt-op")
        v = agentic_quote_blindness(e)
        self.assertFalse(v.allowed)
        self.assertIn("retail:wtp_scored", v.reason)


class AssistantFactGateTest(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = ClaimEvidenceRegistry(self.auth)
        self.reg.issue(
            receipt_id="cl-1", assistant_id="as-1", item_id="i-1",
            claim_kind="price", claim_text="$9.99 in stock",
            evidence_digest=HEX64, observed_at=T0,
            authority_id="bench-rt-op", authority_secret=SEC)

    def test_allow_evidenced_claim(self):
        v = assistant_fact_gate(self.reg, "cl-1", "i-1", "price",
                                "$9.99 in stock", T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_unverified_claim(self):
        v = assistant_fact_gate(self.reg, "cl-missing", "i-1", "price",
                                "$9.99 in stock", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:unverified_claim", v.reason)
        self.assertEqual(v.classification, "non_authoritative")

    def test_deny_claim_mismatch(self):
        v = assistant_fact_gate(self.reg, "cl-1", "i-1", "price",
                                "$8.99 in stock", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:claim_mismatch", v.reason)


class DarkPatternScreenTest(unittest.TestCase):
    def test_allow_clean_checkout(self):
        s = CheckoutScreening("cs-1", "m-1", (), T0, "bench-rt-op")
        self.assertTrue(dark_pattern_screen(s).allowed)

    def test_deny_roach_motel(self):
        s = CheckoutScreening("cs-2", "m-1",
                              ("roach_motel", "fake_countdown"),
                              T0, "bench-rt-op")
        v = dark_pattern_screen(s)
        self.assertFalse(v.allowed)
        self.assertIn("retail:dark_pattern", v.reason)


class ShashaReceiptTest(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = ShashaRegistry(self.auth)
        self.reg.issue(
            receipt_id="ss-1", platform_id="p-1", item_id="i-1",
            cohort_a="new", price_a_minor=8000,
            cohort_b="returning", price_b_minor=9000,
            justification="Cohort A shows a first-order coupon applied at checkout.",
            published_at=T0, authority_id="bench-rt-op", authority_secret=SEC)

    def test_allow_justified_gap(self):
        v = shasha_receipt(self.reg, "ss-1", "i-1", 8000, "new", T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_unjustified_gap(self):
        v = shasha_receipt(self.reg, "ss-missing", "i-1", 8000, "new", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:price_discrimination", v.reason)

    def test_deny_price_mismatch(self):
        v = shasha_receipt(self.reg, "ss-1", "i-1", 7777, "new", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:shasha_price_mismatch", v.reason)


class MerchantRuleDisclosureTest(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = MerchantRuleRegistry(self.auth)
        self.reg.issue(
            receipt_id="mr-1", platform_id="p-1", rules_version="2026-q4",
            ranking_rules_digest=HEX64, traffic_allocation_digest=HEX64,
            commission_schedule_digest=HEX64, published_at=T0,
            authority_id="bench-rt-op", authority_secret=SEC)

    def test_allow_disclosed(self):
        v = merchant_rule_disclosure(self.reg, "mr-1", "p-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_opaque(self):
        v = merchant_rule_disclosure(self.reg, "mr-missing", "p-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:merchant_opaque", v.reason)


class QuotaTransparencyTest(unittest.TestCase):
    def test_allow_disclosed_no_auto_termination(self):
        d = QuotaDisclosure("q-1", "site-1", 180.0, 3600,
                            False, False, T0, "bench-rt-op")
        self.assertTrue(quota_transparency(d).allowed)

    def test_deny_auto_termination_without_review(self):
        d = QuotaDisclosure("q-2", "site-1", 220.0, 3600,
                            True, False, T0, "bench-rt-op")
        v = quota_transparency(d)
        self.assertFalse(v.allowed)
        self.assertIn("retail:auto_termination", v.reason)

    def test_allow_auto_termination_with_review(self):
        d = QuotaDisclosure("q-3", "site-1", 220.0, 3600,
                            True, True, T0, "bench-rt-op")
        self.assertTrue(quota_transparency(d).allowed)


class WearableSurveillanceBudgetTest(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = WearableCollectionRegistry(self.auth)
        self.reg.issue(
            receipt_id="wb-1", operator_id="op-1", device_kind="smart_glasses",
            purposes=("proof_of_delivery", "navigation"),
            retention_days=30, collected_at=T0,
            authority_id="bench-rt-op", authority_secret=SEC)

    def test_allow_in_scope_use(self):
        v = wearable_surveillance_budget(self.reg, "wb-1",
                                         ("proof_of_delivery",), T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_undeclared(self):
        v = wearable_surveillance_budget(self.reg, "wb-missing",
                                         ("navigation",), T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:wearable_undeclared", v.reason)

    def test_deny_overreach(self):
        v = wearable_surveillance_budget(self.reg, "wb-1",
                                         ("navigation", "productivity_scoring"),
                                         T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("retail:wearable_overreach", v.reason)


class SignatureIntegrityTest(unittest.TestCase):
    def test_tampered_signature_is_invalid(self):
        auth = _auth()
        reg = PriceDisclosureRegistry(auth)
        r = reg.issue(
            receipt_id="pd-t", merchant_id="m-1", item_id="i-1",
            personalized_price_minor=9999,
            disclosure_text="Personalized price disclosure.",
            shown_at=T0, authority_id="bench-rt-op", authority_secret=SEC)
        tampered = PriceDisclosureReceipt(
            receipt_id=r.receipt_id, merchant_id=r.merchant_id,
            item_id=r.item_id,
            personalized_price_minor=r.personalized_price_minor,
            disclosure_text=r.disclosure_text, shown_at=r.shown_at,
            authority_id=r.authority_id,
            authority_pubkey_hex=r.authority_pubkey_hex,
            signature_hex="ff" * 64, prev_digest=r.prev_digest,
            receipt_digest=r.receipt_digest)
        reg2 = PriceDisclosureRegistry(auth)
        reg2.log.append(tampered)
        self.assertRaises(RetailError, reg2.issue,
                          "pd-t2", "m-1", "i-1", 9999,
                          "Personalized price disclosure.",
                          T0, "bench-rt-op", SEC)


if __name__ == "__main__":
    unittest.main()
