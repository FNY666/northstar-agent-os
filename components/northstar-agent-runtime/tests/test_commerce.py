"""Tests for commerce.py (one-hundred-twenty-fourth batch).

Deterministic: fixed 32-byte seeds, injected integer timestamps.
"""

import unittest

from commerce import (
    COMMERCE_SCHEMA_VERSION,
    CommerceError,
    authentication_evidence,
    biometric_capture_receipt,
    biometric_deletion_receipt,
    check_biometric_collection,
    check_biometric_deletion,
    check_model_substitution,
    check_order_terms,
    check_passport_binding,
    check_preview_use,
    commerce_audit_event,
    issue_authentication_claim,
    issue_preview_receipt,
    likeness_creep_gate,
    likeness_grant_receipt,
    model_substitution_disclosure,
    passport_binding_receipt,
    terms_read_receipt,
)

T0 = 1_700_000_000
AUTH = bytes([9]) * 32
OTHER = bytes([7]) * 32
D1 = "ab" * 32
D2 = "cd" * 32
D3 = "ef" * 32


def _terms(order_id="ord-1", product=D1, prev="genesis"):
    return terms_read_receipt(
        receipt_id="tr-1",
        order_id=order_id,
        agent_id="agent-shopper",
        product_digest=product,
        size_chart_digest=D2,
        return_policy_digest=D3,
        total_price_cents=5999,
        fees_cents=499,
        authority_secret=AUTH,
        issued_by="store-ops",
        issued_at=T0,
        expires_at=T0 + 3600,
        prev_digest=prev,
    )


def _grant(classes=("catalog-apparel",), prev="genesis"):
    return likeness_grant_receipt(
        receipt_id="lg-1",
        likeness_digest=D1,
        granted_classes=classes,
        grantor="model-agency",
        authority_secret=AUTH,
        issued_by="store-ops",
        issued_at=T0,
        expires_at=T0 + 3600,
        prev_digest=prev,
    )


def _bio_capture(prev="genesis"):
    return biometric_capture_receipt(
        receipt_id="bc-1",
        subject_id="shopper-1",
        purpose="virtual-tryon",
        biometric_kinds=("body_measurements",),
        retention_days=7,
        deletion_mechanism_digest=D2,
        authority_secret=AUTH,
        issued_by="store-ops",
        issued_at=T0,
        prev_digest=prev,
    )


class TestTermsRead(unittest.TestCase):
    def test_allow_order_with_terms_read(self):
        v = check_order_terms([_terms()], order_id="ord-1", product_digest=D1,
                              check_time=T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_deny_no_receipt(self):
        v = check_order_terms([], order_id="ord-1", product_digest=D1,
                              check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("unverifiable_terms", v.reason)

    def test_deny_product_mismatch(self):
        v = check_order_terms([_terms()], order_id="ord-1", product_digest=D2,
                              check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("unverifiable_terms", v.reason)

    def test_deny_expired_receipt(self):
        v = check_order_terms([_terms()], order_id="ord-1", product_digest=D1,
                              check_time=T0 + 7200)
        self.assertFalse(v.allowed)

    def test_issuance_rejects_negative_fees(self):
        with self.assertRaises(CommerceError):
            terms_read_receipt(
                receipt_id="x", order_id="o", agent_id="a",
                product_digest=D1, size_chart_digest=D2,
                return_policy_digest=D3, total_price_cents=100,
                fees_cents=-5, authority_secret=AUTH, issued_by="s",
                issued_at=T0, expires_at=T0 + 10,
            )

    def test_issuance_rejects_zero_total(self):
        with self.assertRaises(CommerceError):
            terms_read_receipt(
                receipt_id="x", order_id="o", agent_id="a",
                product_digest=D1, size_chart_digest=D2,
                return_policy_digest=D3, total_price_cents=0,
                fees_cents=0, authority_secret=AUTH, issued_by="s",
                issued_at=T0, expires_at=T0 + 10,
            )

    def test_tampered_log_denies_chain_broken(self):
        r = _terms()
        tampered = type(r)(**{**r.__dict__, "fees_cents": 1})
        v = check_order_terms([tampered], order_id="ord-1", product_digest=D1,
                              check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("chain_broken", v.reason)


class TestLikenessCreep(unittest.TestCase):
    def test_allow_use_within_grant(self):
        v = likeness_creep_gate([_grant()], likeness_digest=D1,
                                use_class="catalog-apparel", check_time=T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_creep_to_sexualized_ad(self):
        v = likeness_creep_gate([_grant()], likeness_digest=D1,
                                use_class="sexualized-ad", check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("likeness_creep", v.reason)

    def test_deny_no_grant(self):
        v = likeness_creep_gate([], likeness_digest=D1,
                                use_class="catalog-apparel", check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("no_likeness_grant", v.reason)

    def test_unknown_class_raises(self):
        with self.assertRaises(CommerceError):
            likeness_creep_gate([_grant()], likeness_digest=D1,
                                use_class="deepfake-meme", check_time=T0 + 10)

    def test_empty_class_list_raises(self):
        with self.assertRaises(CommerceError):
            likeness_grant_receipt(
                receipt_id="x", likeness_digest=D1, granted_classes=(),
                grantor="g", authority_secret=AUTH, issued_by="s",
                issued_at=T0, expires_at=T0 + 10,
            )


class TestBiometric(unittest.TestCase):
    def test_allow_collection_with_receipt(self):
        v = check_biometric_collection(
            [_bio_capture()], subject_id="shopper-1",
            purpose="virtual-tryon", biometric_kinds=("body_measurements",),
            check_time=T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_no_receipt(self):
        v = check_biometric_collection(
            [], subject_id="shopper-1", purpose="virtual-tryon",
            biometric_kinds=("body_measurements",), check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("no_biometric_receipt", v.reason)

    def test_deny_purpose_mismatch(self):
        v = check_biometric_collection(
            [_bio_capture()], subject_id="shopper-1",
            purpose="ad-targeting", biometric_kinds=("body_measurements",),
            check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("biometric_purpose_violation", v.reason)

    def test_deny_uncaptured_kind(self):
        v = check_biometric_collection(
            [_bio_capture()], subject_id="shopper-1",
            purpose="virtual-tryon", biometric_kinds=("facial_geometry",),
            check_time=T0 + 10)
        self.assertFalse(v.allowed)

    def test_within_retention_allows(self):
        v = check_biometric_deletion([_bio_capture()], [], subject_id="shopper-1",
                                    check_time=T0 + 3 * 86400)
        self.assertTrue(v.allowed)

    def test_expired_without_deletion_receipt_denies(self):
        v = check_biometric_deletion([_bio_capture()], [], subject_id="shopper-1",
                                    check_time=T0 + 30 * 86400)
        self.assertFalse(v.allowed)
        self.assertIn("deletion_unverified", v.reason)

    def test_expired_with_deletion_receipt_allows(self):
        cap = _bio_capture()
        deletion = biometric_deletion_receipt(
            receipt_id="del-1", capture=cap, deletion_method_digest=D3,
            authority_secret=AUTH, issued_by="store-ops", deleted_at=T0 + 8 * 86400)
        v = check_biometric_deletion([cap], [deletion], subject_id="shopper-1",
                                    check_time=T0 + 30 * 86400)
        self.assertTrue(v.allowed)


class TestPreview(unittest.TestCase):
    def _preview(self):
        return issue_preview_receipt(
            receipt_id="pv-1", preview_id="tryon-1", content_digest=D1,
            authority_secret=AUTH, issued_by="store-ops", issued_at=T0)

    def test_view_only_allows_non_authoritative(self):
        v = check_preview_use(self._preview(), use="view-only")
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "non_authoritative")

    def test_fit_decision_denies(self):
        v = check_preview_use(self._preview(), use="fit-decision")
        self.assertFalse(v.allowed)
        self.assertIn("fit_guarantee_claim", v.reason)


class TestAuthentication(unittest.TestCase):
    def _claim(self, **over):
        kw = dict(
            claim_id="ac-1", item_digest=D1, verdict="authentic",
            claimed_confidence_bps=9400, evidence_digest=D2,
            evidence_tier="third-party", value_class="standard",
            human_review=False, authority_secret=AUTH, issued_by="store-ops",
            issued_at=T0, expires_at=T0 + 3600)
        kw.update(over)
        return issue_authentication_claim(**kw)

    def test_allow_graded_claim(self):
        v = authentication_evidence([self._claim()], item_digest=D1,
                                   check_time=T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "non_authoritative")

    def test_deny_vendor_claim_above_ceiling(self):
        v = authentication_evidence(
            [self._claim(evidence_tier="vendor-declared",
                         claimed_confidence_bps=9910)],
            item_digest=D1, check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("ungraded_auth_claim", v.reason)

    def test_deny_high_value_without_human_review(self):
        v = authentication_evidence(
            [self._claim(value_class="high", human_review=False)],
            item_digest=D1, check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("human_review_required", v.reason)

    def test_allow_high_value_with_human_review(self):
        v = authentication_evidence(
            [self._claim(value_class="high", human_review=True)],
            item_digest=D1, check_time=T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_no_claim(self):
        v = authentication_evidence([], item_digest=D1, check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("no_auth_claim", v.reason)


class TestPassport(unittest.TestCase):
    def _binding(self):
        return passport_binding_receipt(
            receipt_id="pb-1", listing_digest=D1, passport_digest=D2,
            passport_scheme="aura", authority_secret=AUTH, issued_by="store-ops",
            issued_at=T0, expires_at=T0 + 3600)

    def test_allow_matching_passport(self):
        v = check_passport_binding([self._binding()], listing_digest=D1,
                                   passport_digest=D2, check_time=T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_mismatch(self):
        v = check_passport_binding([self._binding()], listing_digest=D1,
                                   passport_digest=D3, check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("passport_mismatch", v.reason)

    def test_deny_unbound_listing(self):
        v = check_passport_binding([], listing_digest=D1, passport_digest=D2,
                                   check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("passport_mismatch", v.reason)


class TestSubstitution(unittest.TestCase):
    def _disclosure(self, model_type="ai"):
        return model_substitution_disclosure(
            receipt_id="ms-1", catalog_item_digest=D1, model_type=model_type,
            authority_secret=AUTH, issued_by="store-ops",
            issued_at=T0, expires_at=T0 + 3600)

    def test_allow_human_no_disclosure_needed(self):
        v = check_model_substitution([], catalog_item_digest=D1,
                                     actual_model_type="human",
                                     check_time=T0 + 10)
        self.assertTrue(v.allowed)

    def test_allow_disclosed_ai(self):
        v = check_model_substitution([self._disclosure()], catalog_item_digest=D1,
                                     actual_model_type="ai", check_time=T0 + 10)
        self.assertTrue(v.allowed)

    def test_deny_undisclosed_ai(self):
        v = check_model_substitution([], catalog_item_digest=D1,
                                     actual_model_type="ai",
                                     check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("hidden_model_substitution", v.reason)

    def test_deny_false_disclosure(self):
        v = check_model_substitution([self._disclosure("ai-assisted")],
                                     catalog_item_digest=D1,
                                     actual_model_type="ai",
                                     check_time=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("hidden_model_substitution", v.reason)


class TestAuditEvent(unittest.TestCase):
    def test_event_shape(self):
        ev = commerce_audit_event("unverifiable_terms", "no read receipt")
        self.assertEqual(ev["event"], "commerce.unverifiable_terms")
        self.assertEqual(ev["schema_version"], COMMERCE_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
