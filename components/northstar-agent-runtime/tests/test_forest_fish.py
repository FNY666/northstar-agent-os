"""Tests for forest_fish.py (one-hundred-thirty-third batch)."""

import unittest

from ed25519 import public_key

from forest_fish import (
    CLASS_LEAD,
    CLASS_NON_AUTHORITATIVE,
    DENY_ANOMALY_IS_NOT_PERSON,
    DENY_DATA_LOCKIN,
    DENY_INCOMPLETE_BINDING,
    DENY_LOW_CONFIDENCE_CATCH,
    DENY_NO_FPIC,
    DENY_OUT_OF_REGION_MODEL,
    DENY_PURPOSE_CREEP,
    DENY_UNCERTIFIED_CLAIM,
    ForestFishError,
    aquaculture_data_portability,
    catch_confidence_gate,
    dark_vessel_probe,
    em_privacy_receipt,
    eudr_evidence_receipt,
    indigenous_data_receipt,
    issue_aquaculture_disclosure,
    issue_catch_estimate,
    issue_em_privacy_receipt,
    issue_eudr_certificate,
    issue_indigenous_data_receipt,
    issue_livelihood_allowlist,
    issue_wildfire_model_card,
    livelihood_exemption,
    wildfire_experimental_label,
)


T0 = 1_700_000_000
AUTHORITY = bytes(range(32))
OTHER = bytes([5]) * 32
AUTH_PUB = public_key(AUTHORITY).hex()
DIGEST = "aa" * 32
DIGEST2 = "bb" * 32
DIGEST3 = "cc" * 32


def _allowlist(**over):
    kw = dict(
        receipt_id="al-1",
        territory_id="territory-x",
        community_id="community-x",
        activities=("mahua_gathering", "firewood_collection"),
        issued_by="land-authority",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTHORITY,
        issued_at=T0,
        expires_at=T0 + 10_000,
    )
    kw.update(over)
    return issue_livelihood_allowlist(**kw)


def _fpic(**over):
    kw = dict(
        receipt_id="fpic-1",
        territory_id="territory-x",
        community_id="community-x",
        fpic_grant_digest=DIGEST,
        data_scope="edna_samples",
        collector_pubkey_hex=AUTH_PUB,
        issued_by="land-authority",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTHORITY,
        issued_at=T0,
        expires_at=T0 + 10_000,
    )
    kw.update(over)
    return issue_indigenous_data_receipt(**kw)


def _eudr(**over):
    kw = dict(
        receipt_id="eu-1",
        certificate_id="cert-1",
        shipment_id="ship-1",
        deforestation_free_claim=True,
        evidence_digest=DIGEST,
        evidence_kind="field_audit",
        issued_by="cert-body",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTHORITY,
        issued_at=T0,
        expires_at=T0 + 10_000,
    )
    kw.update(over)
    return issue_eudr_certificate(**kw)


def _em(**over):
    kw = dict(
        receipt_id="em-1",
        vessel_id="vessel-1",
        declared_purpose="stock_assessment",
        retention_days=90,
        issued_by="fisheries-authority",
        authority_pubkey_hex=AUTH_PUB,
        authority_secret=AUTHORITY,
        issued_at=T0,
        expires_at=T0 + 10_000,
    )
    kw.update(over)
    return issue_em_privacy_receipt(**kw)


class LivelihoodExemptionTests(unittest.TestCase):
    def test_listed_activity_blocks_accusation(self):
        v = livelihood_exemption(
            allowlist_log=[_allowlist()],
            territory_id="territory-x",
            activity="mahua_gathering",
            hit_at=T0 + 100,
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith(DENY_ANOMALY_IS_NOT_PERSON))

    def test_unlisted_activity_does_not_block(self):
        v = livelihood_exemption(
            allowlist_log=[_allowlist()],
            territory_id="territory-x",
            activity="medicinal_plants",
            hit_at=T0 + 100,
        )
        self.assertTrue(v.allowed)

    def test_expired_allowlist_does_not_block(self):
        v = livelihood_exemption(
            allowlist_log=[_allowlist()],
            territory_id="territory-x",
            activity="mahua_gathering",
            hit_at=T0 + 20_000,
        )
        self.assertTrue(v.allowed)

    def test_tampered_allowlist_raises(self):
        good = _allowlist()
        bad = good.__class__(**{**good.__dict__, "signature_hex": "00" * 64})
        with self.assertRaises(ForestFishError):
            livelihood_exemption(
                allowlist_log=[bad],
                territory_id="territory-x",
                activity="mahua_gathering",
                hit_at=T0 + 100,
            )


class IndigenousDataTests(unittest.TestCase):
    def test_live_fpic_allows(self):
        v = indigenous_data_receipt(
            receipt_log=[_fpic()],
            territory_id="territory-x",
            data_scope="edna_samples",
            use_time=T0 + 100,
        )
        self.assertTrue(v.allowed)

    def test_scope_mismatch_denies(self):
        v = indigenous_data_receipt(
            receipt_log=[_fpic()],
            territory_id="territory-x",
            data_scope="geospatial",
            use_time=T0 + 100,
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith(DENY_NO_FPIC))

    def test_expired_fpic_denies(self):
        v = indigenous_data_receipt(
            receipt_log=[_fpic()],
            territory_id="territory-x",
            data_scope="edna_samples",
            use_time=T0 + 20_000,
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith(DENY_NO_FPIC))

    def test_wrong_key_receipt_raises(self):
        bad = _fpic(authority_secret=OTHER)
        with self.assertRaises(ForestFishError):
            indigenous_data_receipt(
                receipt_log=[bad],
                territory_id="territory-x",
                data_scope="edna_samples",
                use_time=T0 + 100,
            )


class EudrTests(unittest.TestCase):
    def test_bound_evidence_allows(self):
        v = eudr_evidence_receipt(
            certificate_log=[_eudr()], certificate_id="cert-1", use_time=T0 + 100
        )
        self.assertTrue(v.allowed)

    def test_no_evidence_is_non_authoritative(self):
        v = eudr_evidence_receipt(
            certificate_log=[_eudr(evidence_digest="")],
            certificate_id="cert-1",
            use_time=T0 + 100,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)
        self.assertTrue(v.reason.startswith(DENY_UNCERTIFIED_CLAIM))

    def test_self_declared_is_non_authoritative(self):
        v = eudr_evidence_receipt(
            certificate_log=[_eudr(evidence_kind="self_declared")],
            certificate_id="cert-1",
            use_time=T0 + 100,
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith(DENY_UNCERTIFIED_CLAIM))


class DarkVesselTests(unittest.TestCase):
    def _probe(self, **over):
        kw = dict(
            receipt_id="dv-1",
            lead_id="lead-1",
            vessel_id="vessel-9",
            sar_digest=DIGEST,
            rf_digest=DIGEST2,
            behavior_digest=DIGEST3,
            analyst="analyst-1",
            authority_pubkey_hex=AUTH_PUB,
            authority_secret=AUTHORITY,
            issued_at=T0,
        )
        kw.update(over)
        return dark_vessel_probe(**kw)

    def test_complete_binding_is_lead_not_accusation(self):
        v = self._probe()
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_LEAD)

    def test_incomplete_binding_not_actionable(self):
        v = self._probe(rf_digest="")
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith(DENY_INCOMPLETE_BINDING))

    def test_malformed_digest_raises(self):
        with self.assertRaises(ForestFishError):
            self._probe(sar_digest="not-hex")


class EmPrivacyTests(unittest.TestCase):
    def test_declared_purpose_allows(self):
        v = em_privacy_receipt(
            receipt_log=[_em()],
            vessel_id="vessel-1",
            use_purpose="stock_assessment",
            use_time=T0 + 100,
        )
        self.assertTrue(v.allowed)

    def test_purpose_creep_denies(self):
        v = em_privacy_receipt(
            receipt_log=[_em()],
            vessel_id="vessel-1",
            use_purpose="quota_compliance",
            use_time=T0 + 100,
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith(DENY_PURPOSE_CREEP))

    def test_no_receipt_denies(self):
        v = em_privacy_receipt(
            receipt_log=[],
            vessel_id="vessel-1",
            use_purpose="stock_assessment",
            use_time=T0 + 100,
        )
        self.assertFalse(v.allowed)


class AquacultureTests(unittest.TestCase):
    def _disclosure(self, **over):
        kw = dict(
            receipt_id="aq-1",
            disclosure_id="disc-1",
            operator_id="op-1",
            sensor_data_portable=False,
            export_formats=(),
            lockin_terms_digest="",
            issued_by="regulator",
            authority_pubkey_hex=AUTH_PUB,
            authority_secret=AUTHORITY,
            issued_at=T0,
        )
        kw.update(over)
        return issue_aquaculture_disclosure(**kw)

    def test_portable_allows(self):
        v = aquaculture_data_portability(
            disclosure=self._disclosure(
                sensor_data_portable=True, export_formats=("csv", "json")
            )
        )
        self.assertTrue(v.allowed)

    def test_disclosed_lockin_allows(self):
        v = aquaculture_data_portability(
            disclosure=self._disclosure(lockin_terms_digest=DIGEST)
        )
        self.assertTrue(v.allowed)

    def test_undisclosed_lockin_denies(self):
        v = aquaculture_data_portability(disclosure=self._disclosure())
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason.startswith(DENY_DATA_LOCKIN))


class CatchConfidenceTests(unittest.TestCase):
    def _estimate(self, confidence):
        return issue_catch_estimate(
            receipt_id="ce-1",
            estimate_id="est-1",
            fishery_id="fishery-1",
            estimate_t=1200.0,
            confidence=confidence,
            method_digest=DIGEST,
            issued_by="science-body",
            authority_pubkey_hex=AUTH_PUB,
            authority_secret=AUTHORITY,
            issued_at=T0,
        )

    def test_high_confidence_may_be_evidence(self):
        v = catch_confidence_gate(estimate=self._estimate(0.92))
        self.assertTrue(v.allowed)

    def test_low_confidence_is_lead_only(self):
        v = catch_confidence_gate(estimate=self._estimate(0.55))
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_LEAD)
        self.assertTrue(v.reason.startswith(DENY_LOW_CONFIDENCE_CATCH))


class WildfireTests(unittest.TestCase):
    def _card(self, **over):
        kw = dict(
            receipt_id="wf-1",
            model_id="model-1",
            model_digest=DIGEST,
            training_region="au-vic",
            validation_regions=("au-nsw",),
            issued_by="fire-agency",
            authority_pubkey_hex=AUTH_PUB,
            authority_secret=AUTHORITY,
            issued_at=T0,
        )
        kw.update(over)
        return issue_wildfire_model_card(**kw)

    def test_covered_region_allows(self):
        v = wildfire_experimental_label(
            card=self._card(), deployment_region="au-nsw"
        )
        self.assertTrue(v.allowed)

    def test_out_of_region_is_non_authoritative(self):
        v = wildfire_experimental_label(
            card=self._card(), deployment_region="br-amazon"
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)
        self.assertTrue(v.reason.startswith(DENY_OUT_OF_REGION_MODEL))

    def test_chain_break_raises(self):
        good = self._card()
        chained = self._card(receipt_id="wf-2", prev_digest=good.receipt_digest)
        # skip the first entry: chain must start at genesis
        from forest_fish import _check_chain

        with self.assertRaises(ForestFishError):
            _check_chain([chained], "wildfire-card")


if __name__ == "__main__":
    unittest.main()
