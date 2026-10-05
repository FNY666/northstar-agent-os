"""Tests for housing_ai_agents (one-hundred-forty-second batch)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import housing
import housing_ai_agents as haa
from housing_ai_agents import (
    DENY_NO_PROBE,
    DENY_PROBE_SELF_AUDITED,
    DENY_PROBE_TAMPERED,
    DENY_VOUCHER_SLICE_MISSING,
    DENY_VOUCHER_INCOME,
    DENY_VOUCHER_POLICY_UNDECLARED,
    DENY_NO_APPEAL,
    DENY_APPEAL_TAMPERED,
    DENY_COORDINATION,
    DENY_RECENCY,
    DENY_AUTO_ACCEPT,
    DENY_AVM_REVIEW,
    DENY_STEERING,
    DENY_DECEPTIVE_LISTING,
    DENY_ACTION_NO_APPEAL,
    DENY_ACTION_TAMPERED,
    HousingAIError,
    screening_fairness_probe,
    voucher_income_gate,
    issue_appeal_receipt,
    check_appeal,
    appeal_window,
    declare_training_data,
    rent_coordination_probe,
    rent_recommendation_gate,
    avm_confidence_gate,
    steering_probe,
    check_steering_probe_receipt,
    issue_photo_edit_receipt,
    listing_truth_receipt,
    adverse_action_receipt,
    check_adverse_action,
)

SEC = bytes(range(1, 33))  # deterministic 32-byte secret
SEC2 = bytes(range(33, 65))
T0 = 1_800_000_000


def make_probe(slices=("voucher_holders", "race_ethnicity", "familial_status"),
               secret=SEC, measured=T0, expires=T0 + 365 * 86400):
    return housing.issue_fairness_probe(
        probe_id="probe-1",
        model_digest="ab" * 32,
        probe_type="disparate_impact",
        demographic_slices=list(slices),
        probe_digest="cd" * 32,
        vendor_id="vendor-a",
        vendor_secret=secret,
        measured_at=measured,
        expires_at=expires,
    )


class ScreeningProbeTests(unittest.TestCase):
    def test_allow_fully_compliant_probe(self):
        v = screening_fairness_probe(
            [make_probe()], model_digest="ab" * 32,
            auditor_id="auditor-x", check_time=T0 + 100)
        self.assertTrue(v.allowed)

    def test_deny_no_receipt(self):
        v = screening_fairness_probe(
            [], model_digest="ab" * 32, auditor_id="auditor-x",
            check_time=T0 + 100)
        self.assertEqual(v.reason, DENY_NO_PROBE)

    def test_deny_voucher_slice_missing(self):
        v = screening_fairness_probe(
            [make_probe(slices=("race_ethnicity", "familial_status"))],
            model_digest="ab" * 32, auditor_id="auditor-x",
            check_time=T0 + 100)
        self.assertEqual(v.reason, DENY_VOUCHER_SLICE_MISSING)

    def test_deny_self_audited(self):
        v = screening_fairness_probe(
            [make_probe()], model_digest="ab" * 32,
            auditor_id="vendor-a", check_time=T0 + 100)
        self.assertEqual(v.reason, DENY_PROBE_SELF_AUDITED)

    def test_deny_tampered_receipt(self):
        probe = make_probe()
        bad = housing.FairnessProbeReceipt(
            probe_id=probe.probe_id, model_digest=probe.model_digest,
            probe_type=probe.probe_type,
            demographic_slices=probe.demographic_slices,
            probe_digest=probe.probe_digest, vendor_id=probe.vendor_id,
            vendor_pubkey_hex=probe.vendor_pubkey_hex,
            signature_hex=probe.signature_hex,
            measured_at=probe.measured_at, expires_at=probe.expires_at,
            prev_digest=probe.prev_digest,
            probe_receipt_digest="ff" * 32,
            schema_version=probe.schema_version)
        v = screening_fairness_probe(
            [bad], model_digest="ab" * 32, auditor_id="auditor-x",
            check_time=T0 + 100)
        self.assertEqual(v.reason, DENY_PROBE_TAMPERED)


class VoucherGateTests(unittest.TestCase):
    def test_allow_declared_accept(self):
        v = voucher_income_gate(
            voucher_policy_declared=True, accepts_vouchers=True,
            screening_rules=[{"rule_id": "r1", "treats_voucher_income": "accept"}])
        self.assertTrue(v.allowed)

    def test_deny_undeclared_policy(self):
        v = voucher_income_gate(
            voucher_policy_declared=False, accepts_vouchers=False,
            screening_rules=[])
        self.assertEqual(v.reason, DENY_VOUCHER_POLICY_UNDECLARED)

    def test_deny_excluding_rule(self):
        v = voucher_income_gate(
            voucher_policy_declared=True, accepts_vouchers=True,
            screening_rules=[
                {"rule_id": "r1", "treats_voucher_income": "accept"},
                {"rule_id": "r2", "treats_voucher_income": "exclude"}])
        self.assertEqual(v.reason, DENY_VOUCHER_INCOME)
        self.assertEqual(v.offending_rules, ("r2",))

    def test_malformed_treatment_raises(self):
        with self.assertRaises(HousingAIError):
            voucher_income_gate(
                voucher_policy_declared=True, accepts_vouchers=True,
                screening_rules=[{"rule_id": "r1", "treats_voucher_income": "ignore"}])


class AppealWindowTests(unittest.TestCase):
    def make_appeal(self, digest="ab" * 32, window=30, secret=SEC, issued=T0):
        return issue_appeal_receipt(
            appeal_id="a1", decision_digest=digest, channel="email",
            contact="appeals@example.com", window_days=window,
            human_reviewer_id="reviewer-1", issuer_secret=secret,
            issued_at=issued)

    def test_allow_live_appeal(self):
        v = appeal_window(self.make_appeal(), decision_digest="ab" * 32,
                          check_time=T0 + 100)
        self.assertTrue(v.allowed)

    def test_deny_no_appeal(self):
        v = appeal_window(None, decision_digest="ab" * 32, check_time=T0 + 100)
        self.assertEqual(v.reason, DENY_NO_APPEAL)

    def test_short_window_raises(self):
        with self.assertRaises(HousingAIError):
            self.make_appeal(window=7)

    def test_deny_tampered_appeal(self):
        appeal = self.make_appeal()
        bad = haa.AppealReceipt(
            appeal_id=appeal.appeal_id, decision_digest=appeal.decision_digest,
            channel=appeal.channel, contact=appeal.contact,
            window_days=appeal.window_days,
            human_reviewer_id=appeal.human_reviewer_id,
            issued_at=appeal.issued_at, expires_at=appeal.expires_at,
            issuer_pubkey_hex=appeal.issuer_pubkey_hex,
            signature_hex=appeal.signature_hex,
            prev_digest=appeal.prev_digest,
            appeal_digest="ff" * 32, schema_version=appeal.schema_version)
        v = check_appeal(bad, decision_digest="ab" * 32, check_time=T0 + 100)
        self.assertEqual(v.reason, DENY_APPEAL_TAMPERED)

    def test_deny_expired_appeal(self):
        v = appeal_window(self.make_appeal(window=30),
                          decision_digest="ab" * 32,
                          check_time=T0 + 31 * 86400)
        self.assertFalse(v.allowed)


class CoordinationTests(unittest.TestCase):
    def make_receipt(self, sources):
        return declare_training_data(
            receipt_id="td1", model_digest="ab" * 32, sources=sources,
            declared_by="deployer-1", declared_at=T0)

    def test_allow_isolated_aged_data(self):
        r = self.make_receipt([{
            "source_id": "s1", "source_digest": "cd" * 32,
            "min_age_days": 400, "contains_competitor_nonpublic": False}])
        v = rent_coordination_probe(r, model_digest="ab" * 32)
        self.assertTrue(v.allowed)

    def test_deny_competitor_nonpublic(self):
        r = self.make_receipt([{
            "source_id": "s1", "source_digest": "cd" * 32,
            "min_age_days": 400, "contains_competitor_nonpublic": True}])
        v = rent_coordination_probe(r, model_digest="ab" * 32)
        self.assertEqual(v.reason, DENY_COORDINATION)

    def test_deny_fresh_training_data(self):
        r = self.make_receipt([{
            "source_id": "s1", "source_digest": "cd" * 32,
            "min_age_days": 30, "contains_competitor_nonpublic": False}])
        v = rent_coordination_probe(r, model_digest="ab" * 32)
        self.assertEqual(v.reason, DENY_RECENCY)

    def test_deny_auto_accept(self):
        v = rent_recommendation_gate(
            rent_value=2500.0, auto_accept=True, basis_digest="cd" * 32)
        self.assertEqual(v.reason, DENY_AUTO_ACCEPT)

    def test_allow_manual_recommendation(self):
        v = rent_recommendation_gate(
            rent_value=2500.0, auto_accept=False, basis_digest="cd" * 32)
        self.assertTrue(v.allowed)


class AVMTests(unittest.TestCase):
    def test_allow_high_confidence_fresh(self):
        v = avm_confidence_gate(
            model_digest="ab" * 32, confidence=0.95, data_as_of=T0 - 30 * 86400,
            use_kind="mortgage_lending", check_time=T0)
        self.assertTrue(v.allowed)

    def test_deny_low_confidence_mortgage(self):
        v = avm_confidence_gate(
            model_digest="ab" * 32, confidence=0.75, data_as_of=T0 - 30 * 86400,
            use_kind="mortgage_lending", check_time=T0)
        self.assertEqual(v.reason, DENY_AVM_REVIEW)
        self.assertTrue(v.requires_human_review)

    def test_deny_stale_data(self):
        v = avm_confidence_gate(
            model_digest="ab" * 32, confidence=0.95, data_as_of=T0 - 200 * 86400,
            use_kind="mortgage_lending", check_time=T0)
        self.assertEqual(v.reason, DENY_AVM_REVIEW)

    def test_malformed_use_kind_raises(self):
        with self.assertRaises(HousingAIError):
            avm_confidence_gate(
                model_digest="ab" * 32, confidence=0.95, data_as_of=T0,
                use_kind="fortune_telling", check_time=T0)


class SteeringSealTests(unittest.TestCase):
    def personas(self):
        a = {"income": "80k", "protected:race": "A"}
        b = {"income": "80k", "protected:race": "B"}
        return a, b

    def test_allow_equivalent_listings(self):
        def fn(p):
            return ["unit-1", "unit-2"]
        a, b = self.personas()
        v = steering_probe(fn, a, b, probe_id="sp1", prober_id="prober-1",
                           prober_secret=SEC, measured_at=T0)
        self.assertTrue(v.allowed)
        self.assertIsNotNone(v.receipt)
        chk = check_steering_probe_receipt(v.receipt)
        self.assertTrue(chk.allowed)

    def test_deny_steering(self):
        def fn(p):
            return ["unit-1"] if p["protected:race"] == "A" else ["unit-9"]
        a, b = self.personas()
        v = steering_probe(fn, a, b, probe_id="sp1", prober_id="prober-1",
                           prober_secret=SEC, measured_at=T0)
        self.assertEqual(v.reason, DENY_STEERING)

    def test_deny_tampered_receipt(self):
        def fn(p):
            return ["unit-1", "unit-2"]
        a, b = self.personas()
        v = steering_probe(fn, a, b, probe_id="sp1", prober_id="prober-1",
                           prober_secret=SEC, measured_at=T0)
        r = v.receipt
        bad = haa.SteeringProbeReceipt(
            probe_id=r.probe_id, listing_fn_digest=r.listing_fn_digest,
            persona_a_digest=r.persona_a_digest,
            persona_b_digest=r.persona_b_digest, overlap=r.overlap,
            prober_id=r.prober_id, prober_pubkey_hex=r.prober_pubkey_hex,
            signature_hex=r.signature_hex, measured_at=r.measured_at,
            prev_digest=r.prev_digest, probe_receipt_digest="ff" * 32,
            schema_version=r.schema_version)
        chk = check_steering_probe_receipt(bad)
        self.assertFalse(chk.allowed)


class ListingTruthTests(unittest.TestCase):
    def test_allow_disclosed_edits(self):
        receipt = issue_photo_edit_receipt(
            receipt_id="pe1", listing_id="L1", photo_digest="ab" * 32,
            edits=["staging"], publisher_id="pub-1", published_at=T0)
        v = listing_truth_receipt(
            listing_id="L1",
            photos=[{"photo_digest": "ab" * 32, "ai_edited": True}],
            edit_receipts=[receipt])
        self.assertTrue(v.allowed)

    def test_deny_undisclosed_ai_edit(self):
        v = listing_truth_receipt(
            listing_id="L1",
            photos=[{"photo_digest": "ab" * 32, "ai_edited": True}],
            edit_receipts=[])
        self.assertEqual(v.reason, DENY_DECEPTIVE_LISTING)

    def test_allow_unedited_photo(self):
        v = listing_truth_receipt(
            listing_id="L1",
            photos=[{"photo_digest": "ab" * 32, "ai_edited": False}],
            edit_receipts=[])
        self.assertTrue(v.allowed)

    def test_none_plus_edits_raises(self):
        with self.assertRaises(HousingAIError):
            issue_photo_edit_receipt(
                receipt_id="pe1", listing_id="L1", photo_digest="ab" * 32,
                edits=["none", "staging"], publisher_id="pub-1",
                published_at=T0)


class AdverseActionTests(unittest.TestCase):
    def make_appeal(self):
        return issue_appeal_receipt(
            appeal_id="a1", decision_digest="ab" * 32, channel="email",
            contact="appeals@example.com", window_days=30,
            human_reviewer_id="reviewer-1", issuer_secret=SEC, issued_at=T0)

    def test_allow_bound_appeal(self):
        action = adverse_action_receipt(
            action_id="aa1", subject_id="s1",
            reasons=["insufficient credit history"],
            appeal=self.make_appeal(), human_decision_digest="cd" * 32,
            acted_at=T0 + 50)
        v = check_adverse_action(action, self.make_appeal(),
                                 check_time=T0 + 100)
        self.assertTrue(v.allowed)

    def test_vague_reason_raises(self):
        with self.assertRaises(HousingAIError):
            adverse_action_receipt(
                action_id="aa1", subject_id="s1",
                reasons=["model output"],
                appeal=self.make_appeal(), human_decision_digest="cd" * 32,
                acted_at=T0 + 50)

    def test_deny_no_appeal(self):
        action = adverse_action_receipt(
            action_id="aa1", subject_id="s1",
            reasons=["insufficient credit history"],
            appeal=self.make_appeal(), human_decision_digest="cd" * 32,
            acted_at=T0 + 50)
        v = check_adverse_action(action, None, check_time=T0 + 100)
        self.assertEqual(v.reason, DENY_ACTION_NO_APPEAL)

    def test_deny_swapped_appeal(self):
        action = adverse_action_receipt(
            action_id="aa1", subject_id="s1",
            reasons=["insufficient credit history"],
            appeal=self.make_appeal(), human_decision_digest="cd" * 32,
            acted_at=T0 + 50)
        other = issue_appeal_receipt(
            appeal_id="a2", decision_digest="ee" * 32, channel="email",
            contact="other@example.com", window_days=30,
            human_reviewer_id="reviewer-2", issuer_secret=SEC2, issued_at=T0)
        v = check_adverse_action(action, other, check_time=T0 + 100)
        self.assertEqual(v.reason, DENY_ACTION_TAMPERED)


if __name__ == "__main__":
    unittest.main()
