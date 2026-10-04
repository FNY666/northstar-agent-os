"""Tests for the sports & fitness AI discipline gates (one-hundred-sixty-sixth batch)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ed25519 import public_key

from sports_agents import (
    MEASUREMENT,
    RULING,
    WELLNESS,
    DataIngestion,
    EvalSuite,
    MarketingCampaign,
    OfficiatingOutput,
    QuotingSession,
    RecommenderDeployment,
    Sanction,
    SyntheticGeneration,
    anti_scraping_circuit_breaker,
    athlete_data_ownership_receipt,
    doping_alert_tiering,
    issue_adjudicator_countersign,
    issue_boundary_declaration,
    issue_likeness_authorization,
    issue_ownership_receipt,
    issue_quiet_mode_receipt,
    issue_responsibility_manifest,
    likeness_registry_pin,
    monitoring_burden_ledger,
    officiating_human_final_gate,
    predatory_marketing_ban,
    refusal_capability_gate,
    responsibility_manifest,
    wellness_boundary_receipt,
    DopingAlert,
    BurdenLedger,
    BoundaryDeclaration,
    SportsError,
)

T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32

SEC = b"sports-test-key-1" + b"0" * 15
assert len(SEC) == 32
PUB = public_key(SEC)


def _sign_countersign(**kw):
    base = dict(
        countersign_id="cs-1",
        referee_id="ref-7",
        referee_name="Ada Ref",
        output_id="out-1",
        evidence_digest=HEX64,
        decision="onside",
        review_started_at=T0,
        reviewed_at=T0 + 30,
        issuer_secret=SEC,
        issuer_pubkey=PUB,
    )
    base.update(kw)
    return issue_adjudicator_countersign(**base)


class OfficiatingGateTests(unittest.TestCase):
    def _output(self, kind=RULING, **kw):
        base = dict(output_id="out-1", match_id="m-1", output_kind=kind, evidence_digest=HEX64)
        base.update(kw)
        return OfficiatingOutput(**base)

    def test_measurement_passes_without_human(self):
        v = officiating_human_final_gate(self._output(MEASUREMENT), None)
        self.assertTrue(v.allowed)
        self.assertEqual(v.tier, "authoritative")

    def test_ruling_with_valid_countersign(self):
        v = officiating_human_final_gate(self._output(), _sign_countersign())
        self.assertTrue(v.allowed)

    def test_ai_only_ruling_denies(self):
        v = officiating_human_final_gate(self._output(), None)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.ai_adjudication")

    def test_rubber_stamp_digest_mismatch(self):
        v = officiating_human_final_gate(
            self._output(), _sign_countersign(evidence_digest=HEX64_B)
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.ai_adjudication")

    def test_zero_length_review_refused_at_issuance(self):
        with self.assertRaises(SportsError):
            _sign_countersign(reviewed_at=T0)

    def test_unknown_output_kind_denies(self):
        v = officiating_human_final_gate(self._output("opinion"), None)
        self.assertFalse(v.allowed)


class OwnershipReceiptTests(unittest.TestCase):
    def _receipt(self, **kw):
        base = dict(
            receipt_id="own-1",
            athlete_id="ath-1",
            collector="fifa",
            storage_operator="fifa-data",
            beneficiaries=("athlete", "league"),
            revocable=True,
            issued_at=T0,
            issuer_secret=SEC,
            issuer_pubkey=PUB,
        )
        base.update(kw)
        return issue_ownership_receipt(**base)

    def test_ingestion_with_receipt(self):
        v = athlete_data_ownership_receipt(
            DataIngestion("ing-1", "ath-1", "biometric_scan", T0 + 10), self._receipt()
        )
        self.assertTrue(v.allowed)

    def test_ingestion_without_receipt_denies(self):
        v = athlete_data_ownership_receipt(
            DataIngestion("ing-1", "ath-1", "biometric_scan", T0 + 10), None
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.no_ownership_receipt")

    def test_athlete_must_be_beneficiary(self):
        with self.assertRaises(SportsError):
            self._receipt(beneficiaries=("league",))

    def test_receipt_issued_after_collection_denies(self):
        v = athlete_data_ownership_receipt(
            DataIngestion("ing-1", "ath-1", "biometric_scan", T0), self._receipt(issued_at=T0 + 10)
        )
        self.assertFalse(v.allowed)


class PredatoryMarketingTests(unittest.TestCase):
    def test_predatory_targeting_whole_class(self):
        v = predatory_marketing_ban(
            MarketingCampaign("c-1", ("predicted_loss", "age"), False, False)
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.predatory_targeting")

    def test_elasticity_score_whole_class(self):
        v = predatory_marketing_ban(
            MarketingCampaign("c-2", ("elasticity_score",), False, False)
        )
        self.assertFalse(v.allowed)

    def test_recognized_harm_harvested_denies(self):
        v = predatory_marketing_ban(
            MarketingCampaign("c-3", ("age",), True, False)
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.harm_recognized_not_prevented")

    def test_clean_campaign_with_intervention(self):
        v = predatory_marketing_ban(MarketingCampaign("c-4", ("age",), True, True))
        self.assertTrue(v.allowed)


class DopingTieringTests(unittest.TestCase):
    def _alert(self, tier="alert", **kw):
        base = dict(
            alert_id="al-1", athlete_id="ath-1", tier=tier,
            evidence_chain_digest=HEX64, observed_at=T0,
        )
        base.update(kw)
        return DopingAlert(**base)

    def test_alert_alone_is_a_lead(self):
        v = doping_alert_tiering(self._alert(), None)
        self.assertTrue(v.allowed)

    def test_sanction_on_unconfirmed_alert_denies(self):
        v = doping_alert_tiering(
            self._alert(),
            Sanction("s-1", "ath-1", ("al-1",), False, T0 + 60),
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.punitive_alert")

    def test_confirmed_violation_sanction_passes(self):
        v = doping_alert_tiering(
            self._alert("violation"),
            Sanction("s-1", "ath-1", ("al-1",), True, T0 + 60),
        )
        self.assertTrue(v.allowed)

    def test_alert_without_evidence_chain_non_authoritative(self):
        v = doping_alert_tiering(self._alert(evidence_chain_digest=""), None)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.unexplained_alert")


class WellnessBoundaryTests(unittest.TestCase):
    def _decl(self, tier=WELLNESS, **kw):
        base = dict(
            agent_id="well-1", declared_tier=tier,
            referral_path="human-dietitian-hotline", issued_at=T0,
            issuer_secret=SEC, issuer_pubkey=PUB,
        )
        base.update(kw)
        return issue_boundary_declaration(**base)

    def test_wellness_within_boundary(self):
        v = wellness_boundary_receipt(self._decl(), ("general_fitness",))
        self.assertTrue(v.allowed)

    def test_wellness_crosses_into_eating_disorder_denies(self):
        v = wellness_boundary_receipt(self._decl(), ("eating_disorder",))
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.medical_boundary_crossing")

    def test_no_referral_path_refused_at_issuance(self):
        with self.assertRaises(SportsError):
            self._decl(referral_path="")


class BurdenLedgerTests(unittest.TestCase):
    def _ledger(self, **kw):
        base = dict(
            agent_id="fit-1", window_days=7, daily_check_ins=2,
            daily_nudges=1, unmet_goal_pushes=0, anxiety_signals=0,
        )
        base.update(kw)
        return BurdenLedger(**base)

    def _quiet(self, burden_bps, **kw):
        base = dict(
            receipt_id="q-1", agent_id="fit-1", degraded_at=T0,
            burden_bps=burden_bps, issuer_secret=SEC, issuer_pubkey=PUB,
        )
        base.update(kw)
        return issue_quiet_mode_receipt(**base)

    def test_low_burden_passes(self):
        v = monitoring_burden_ledger(self._ledger(), None)
        self.assertTrue(v.allowed)

    def test_anxiety_spike_without_quiet_mode_denies(self):
        v = monitoring_burden_ledger(self._ledger(anxiety_signals=2), None)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.burden_overage")

    def test_quiet_mode_covers_burden(self):
        ledger = self._ledger(anxiety_signals=2)
        burden = 2 * 100 + 1 * 60 + 0 * 40 + 2 * 1000
        v = monitoring_burden_ledger(ledger, self._quiet(burden))
        self.assertTrue(v.allowed)

    def test_understated_quiet_receipt_denies(self):
        ledger = self._ledger(anxiety_signals=2)
        v = monitoring_burden_ledger(ledger, self._quiet(100))
        self.assertFalse(v.allowed)


class LikenessRegistryTests(unittest.TestCase):
    def _auth(self, **kw):
        base = dict(
            entry_id="lk-1", person_id="p-1", authorized_operator="op-1",
            purpose="broadcast_replay", expires_at=T0 + 3600,
            issuer_secret=SEC, issuer_pubkey=PUB,
        )
        base.update(kw)
        return issue_likeness_authorization(**base)

    def _req(self, **kw):
        base = dict(
            generation_id="g-1", person_id="p-1", operator="op-1",
            labeled_as_synthetic=True, requested_at=T0,
        )
        base.update(kw)
        return SyntheticGeneration(**base)

    def test_authorized_labeled_generation(self):
        v = likeness_registry_pin(self._req(), self._auth())
        self.assertTrue(v.allowed)

    def test_no_authorization_denies(self):
        v = likeness_registry_pin(self._req(), None)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.unauthorized_likeness")

    def test_expired_authorization_denies(self):
        v = likeness_registry_pin(self._req(), self._auth(expires_at=T0 - 1))
        self.assertFalse(v.allowed)

    def test_unlabeled_synthetic_denies(self):
        v = likeness_registry_pin(self._req(labeled_as_synthetic=False), self._auth())
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.unlabeled_synthetic")


class ManifestTests(unittest.TestCase):
    def _manifest(self, **kw):
        roles = {
            "model_provider": "mp", "deployer": "dep",
            "human_supervisor": "hs", "failure_escalation_contact": "fec",
        }
        base = dict(
            deployment_id="d-1", roles=roles, issued_at=T0,
            issuer_secret=SEC, issuer_pubkey=PUB,
        )
        base.update(kw)
        return issue_responsibility_manifest(**base)

    def test_complete_manifest(self):
        self.assertTrue(responsibility_manifest(self._manifest()).allowed)

    def test_missing_manifest_denies(self):
        v = responsibility_manifest(None)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.incomplete_manifest")

    def test_missing_role_refused_at_issuance(self):
        roles = {"model_provider": "mp"}
        with self.assertRaises(SportsError):
            self._manifest(roles=roles)


class ScrapingCircuitTests(unittest.TestCase):
    def test_normal_quoting_passes(self):
        v = anti_scraping_circuit_breaker(QuotingSession("s-1", 120, True, False))
        self.assertTrue(v.allowed)

    def test_dead_feed_trade_denies(self):
        v = anti_scraping_circuit_breaker(QuotingSession("s-1", 120, False, False))
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.feed_interruption_trade")

    def test_scrape_rate_without_manual_denies(self):
        v = anti_scraping_circuit_breaker(QuotingSession("s-1", 600, True, False))
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.scrape_halt_refused")

    def test_manual_pricing_engaged_passes(self):
        v = anti_scraping_circuit_breaker(QuotingSession("s-1", 900, True, True))
        self.assertTrue(v.allowed)


class RefusalCapabilityTests(unittest.TestCase):
    def _dep(self, **kw):
        base = dict(agent_id="rec-1", refusal_triggers=("chasing_losses",), evaluated_at=T0)
        base.update(kw)
        return RecommenderDeployment(**base)

    def _suite(self, **kw):
        base = dict(
            suite_id="e-1", agent_id="rec-1",
            tests_recommendation_quality=True, tests_refusal_capability=True,
        )
        base.update(kw)
        return EvalSuite(**base)

    def test_full_coverage_passes(self):
        self.assertTrue(refusal_capability_gate(self._dep(), self._suite()).allowed)

    def test_no_refusal_triggers_denies(self):
        v = refusal_capability_gate(self._dep(refusal_triggers=()), self._suite())
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.no_refusal_trigger")

    def test_quality_only_suite_incomplete(self):
        v = refusal_capability_gate(
            self._dep(), self._suite(tests_refusal_capability=False)
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, "sports.incomplete_eval")

    def test_unknown_trigger_denies(self):
        v = refusal_capability_gate(
            self._dep(refusal_triggers=("vibes",)), self._suite()
        )
        self.assertFalse(v.allowed)


class HonestScopingTests(unittest.TestCase):
    def test_docstring_states_limits(self):
        import sports_agents

        self.assertIn("match-fixing", sports_agents.__doc__)
        self.assertIn("deterministic", sports_agents.__doc__)


if __name__ == "__main__":
    unittest.main()
