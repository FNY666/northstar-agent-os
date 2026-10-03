"""Tests for the housing.py fair-housing & coordination-isolation module."""

import unittest

from housing import (
    DENY_AGENT_VERDICT,
    DENY_COORDINATION,
    DENY_MITIGATING_SUPPRESSED,
    DENY_NO_PROBE,
    DENY_PROBE_EXPIRED,
    DENY_PROBE_SLICE_MISMATCH,
    DENY_STEERING,
    DENY_VAGUE_REASON,
    DENY_VENDOR_NO_AUDIT,
    HousingError,
    adverse_action_receipt,
    avm_fairness_receipt,
    build_evidence_pack,
    check_adverse_action,
    check_vendor_admission,
    coordination_isolation,
    countersign_decision,
    declare_source_isolation,
    human_final_gate,
    issue_fairness_probe,
    mitigating_factors,
    steering_probe,
    vendor_liability_receipt,
)

T0 = 1_700_000_000
VENDOR = bytes(range(32))
HUMAN = bytes([3]) * 32
MODEL = "ab" * 32
PROBE = "cd" * 32
AUDIT = "ef" * 32


def _probe(**over):
    kw = dict(
        probe_id="probe-1",
        model_digest=MODEL,
        probe_type="disparate_impact",
        demographic_slices=("black", "latino", "white"),
        probe_digest=PROBE,
        vendor_id="score-vendor",
        vendor_secret=VENDOR,
        measured_at=T0,
        expires_at=T0 + 86_400,
    )
    kw.update(over)
    return issue_fairness_probe(**kw)


def _pack(**over):
    kw = dict(
        pack_id="pack-1",
        subject_id="applicant-9",
        decision_kind="tenant_screening",
        factors={"credit_score_band": "620-659", "income_multiple": "3.1x"},
        evidence_digests=(AUDIT,),
        emitted_at=T0,
    )
    kw.update(over)
    return build_evidence_pack(**kw)


class ProbeTest(unittest.TestCase):
    def test_valid_probe_allows(self):
        v = avm_fairness_receipt(
            [_probe()],
            model_digest=MODEL,
            decision_kind="tenant_screening",
            required_slices=("black", "latino"),
            check_time=T0 + 60,
        )
        self.assertTrue(v.allowed)

    def test_no_probe_denies(self):
        v = avm_fairness_receipt(
            [],
            model_digest=MODEL,
            decision_kind="tenant_screening",
            required_slices=("black",),
            check_time=T0 + 60,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_NO_PROBE)

    def test_wrong_model_digest_denies(self):
        v = avm_fairness_receipt(
            [_probe()],
            model_digest="ff" * 32,
            decision_kind="tenant_screening",
            required_slices=("black",),
            check_time=T0 + 60,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_NO_PROBE)

    def test_expired_probe_denies(self):
        v = avm_fairness_receipt(
            [_probe()],
            model_digest=MODEL,
            decision_kind="tenant_screening",
            required_slices=("black",),
            check_time=T0 + 86_400,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_PROBE_EXPIRED)

    def test_missing_slice_denies(self):
        v = avm_fairness_receipt(
            [_probe()],
            model_digest=MODEL,
            decision_kind="tenant_screening",
            required_slices=("black", "asian"),
            check_time=T0 + 60,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_PROBE_SLICE_MISMATCH)

    def test_empty_slices_rejected_at_issuance(self):
        with self.assertRaises(HousingError):
            _probe(demographic_slices=())

    def test_unknown_probe_type_rejected(self):
        with self.assertRaises(HousingError):
            _probe(probe_type="vibes")


class PackTest(unittest.TestCase):
    def test_clean_pack_allows(self):
        v = human_final_gate(_pack())
        self.assertTrue(v.allowed)

    def test_agent_verdict_denies(self):
        pack = _pack()
        tampered = pack.__class__(
            **{**pack.__dict__, "verdict": "deny"}
        )
        v = human_final_gate(tampered)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_AGENT_VERDICT)


class CountersignTest(unittest.TestCase):
    def _cs(self, pack, **over):
        kw = dict(
            countersign_id="cs-1",
            pack=pack,
            decision="deny",
            decision_maker_id="manager-1",
            decision_maker_secret=HUMAN,
            decided_at=T0 + 120,
            expires_at=T0 + 86_400,
        )
        kw.update(over)
        return countersign_decision(**kw)

    def test_adverse_action_with_specific_reasons(self):
        pack = _pack()
        cs = self._cs(pack)
        action = adverse_action_receipt(
            action_id="act-1",
            subject_id="applicant-9",
            reasons=["insufficient income: 2.1x vs 3.0x required"],
            pack=pack,
            countersign=cs,
            acted_at=T0 + 200,
        )
        v = check_adverse_action(action, pack, cs, check_time=T0 + 300)
        self.assertTrue(v.allowed)

    def test_vague_reason_rejected(self):
        pack = _pack()
        cs = self._cs(pack)
        with self.assertRaises(HousingError):
            adverse_action_receipt(
                action_id="act-2",
                subject_id="applicant-9",
                reasons=["model output"],
                pack=pack,
                countersign=cs,
                acted_at=T0 + 200,
            )

    def test_vague_reason_case_insensitive(self):
        pack = _pack()
        cs = self._cs(pack)
        with self.assertRaises(HousingError):
            adverse_action_receipt(
                action_id="act-3",
                subject_id="applicant-9",
                reasons=["Algorithmic Score"],
                pack=pack,
                countersign=cs,
                acted_at=T0 + 200,
            )

    def test_adverse_requires_human_deny(self):
        pack = _pack()
        cs = self._cs(pack, decision="approve")
        with self.assertRaises(HousingError):
            adverse_action_receipt(
                action_id="act-4",
                subject_id="applicant-9",
                reasons=["insufficient income"],
                pack=pack,
                countersign=cs,
                acted_at=T0 + 200,
            )

    def test_expired_countersign_denies_at_check(self):
        pack = _pack()
        cs = self._cs(pack, decided_at=T0 + 10, expires_at=T0 + 100)
        action = adverse_action_receipt(
            action_id="act-5",
            subject_id="applicant-9",
            reasons=["insufficient income"],
            pack=pack,
            countersign=cs,
            acted_at=T0 + 50,
        )
        v = check_adverse_action(action, pack, cs, check_time=T0 + 200)
        self.assertFalse(v.allowed)


class IsolationTest(unittest.TestCase):
    def _proof(self, feeds):
        return declare_source_isolation(
            proof_id="iso-1",
            model_digest=MODEL,
            data_sources=("county-records", "mls-sold"),
            live_price_feeds=feeds,
            declared_by="pricing-team",
            declared_at=T0,
        )

    def test_clean_sources_allow(self):
        proof = self._proof(
            [{"feed_id": "f1", "provider_id": "own-crawler", "shared_aggregator": False}]
        )
        v = coordination_isolation(proof, model_digest=MODEL)
        self.assertTrue(v.allowed)

    def test_shared_aggregator_denies(self):
        proof = self._proof(
            [{"feed_id": "f1", "provider_id": "mega-aggregator", "shared_aggregator": True}]
        )
        v = coordination_isolation(proof, model_digest=MODEL)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_COORDINATION)


class SteeringTest(unittest.TestCase):
    def test_equivalent_listings_allow(self):
        def listings(persona):
            return ["unit-a", "unit-b", "unit-c"]

        v = steering_probe(
            listings,
            {"income": "80k", "protected:race": "black"},
            {"income": "80k", "protected:race": "white"},
        )
        self.assertTrue(v.allowed)

    def test_steering_denies(self):
        def listings(persona):
            if persona["protected:race"] == "black":
                return ["unit-c"]
            return ["unit-a", "unit-b", "unit-c"]

        v = steering_probe(
            listings,
            {"income": "80k", "protected:race": "black"},
            {"income": "80k", "protected:race": "white"},
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_STEERING)

    def test_non_protected_difference_rejected(self):
        with self.assertRaises(HousingError):
            steering_probe(
                lambda p: ["unit-a"],
                {"income": "80k", "protected:race": "black"},
                {"income": "40k", "protected:race": "black"},
            )


class VendorTest(unittest.TestCase):
    def _admission(self, **over):
        kw = dict(
            admission_id="adm-1",
            vendor_id="score-vendor",
            landlord_id="landlord-1",
            audit_digest=AUDIT,
            auditor_id="independent-auditor",
            admitted_at=T0,
            expires_at=T0 + 86_400,
        )
        kw.update(over)
        return vendor_liability_receipt(**kw)

    def test_admission_allows(self):
        v = check_vendor_admission(
            self._admission(), vendor_id="score-vendor", check_time=T0 + 60
        )
        self.assertTrue(v.allowed)

    def test_no_admission_denies(self):
        v = check_vendor_admission(None, vendor_id="score-vendor", check_time=T0 + 60)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_VENDOR_NO_AUDIT)

    def test_self_certification_rejected(self):
        with self.assertRaises(HousingError):
            self._admission(auditor_id="score-vendor")


class MitigatingTest(unittest.TestCase):
    def test_all_presented_allows(self):
        v = mitigating_factors(
            {"housing_voucher": "section-8 active", "co_signer": "parent guarantee"},
            {"housing_voucher": "section-8 active", "co_signer": "parent guarantee"},
        )
        self.assertTrue(v.allowed)

    def test_suppressed_factor_denies(self):
        v = mitigating_factors(
            {"housing_voucher": "section-8 active"},
            {},
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_MITIGATING_SUPPRESSED)
        self.assertEqual(v.suppressed, ("housing_voucher",))

    def test_empty_declaration_allows(self):
        v = mitigating_factors({}, {})
        self.assertTrue(v.allowed)


if __name__ == "__main__":
    unittest.main()
