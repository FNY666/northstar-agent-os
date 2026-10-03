"""Tests for adjudication.py (one-hundred-eighteenth batch).

Deterministic: fixed 32-byte seeds, injected integer timestamps.
"""

import unittest

from adjudication import (
    ADJUDICATION_SCHEMA_VERSION,
    DENY_BETTING_CONTAMINATION,
    DENY_COACH_DIAGNOSIS,
    DENY_COACH_LABEL_MISSING,
    DENY_NO_ADJUDICATION,
    DENY_NO_DEGRADATION_PLAN,
    DENY_POPULATION_MISMATCH,
    DENY_PURPOSE_CREEP,
    DENY_RESALE,
    AdjudicationError,
    AdjudicationReceipt,
    CoachOutput,
    biometric_purpose_binding,
    check_coach_output,
    check_degradation_plan,
    check_pipeline_mixing,
    check_population_fit,
    final_adjudication_gate,
    grant_biometric_use,
    issue_adjudication_receipt,
    issue_degradation_plan,
    issue_population_receipt,
    revoke_biometric_use,
)

_AUTH_SECRET = bytes(range(32))
_ADJ_PUBKEY = "aa" * 32
_SUBJECT_SECRET = bytes([7]) * 32
_MODEL = "11" * 32
_DECISION = "22" * 32
_PROCEDURE = "33" * 32
_T0 = 1_780_000_000
_T1 = _T0 + 3_600
_EXP = _T0 + 86_400


def _adjudication_receipt(prev="genesis", **over):
    params = dict(
        receipt_id="adj-1",
        decision_digest=_DECISION,
        adjudicator_id="ref-arias",
        adjudicator_pubkey_hex=_ADJ_PUBKEY,
        qualified_scenes=("crowded_scene", "subjective_call"),
        scene_class="crowded_scene",
        authority_secret=_AUTH_SECRET,
        issued_by="competition-authority",
        adjudicated_at=_T0,
        expires_at=_EXP,
        prev_digest=prev,
    )
    params.update(over)
    return issue_adjudication_receipt(**params)


def _population_receipt(**over):
    params = dict(
        receipt_id="pop-1",
        model_digest=_MODEL,
        capability_id="concussion-assist-v2",
        measured_populations=("adult_male_pro",),
        authority_secret=_AUTH_SECRET,
        issued_by="sports-medicine-board",
        measured_at=_T0,
        expires_at=_EXP,
    )
    params.update(over)
    return issue_population_receipt(**params)


def _biometric_grant(**over):
    params = dict(
        receipt_id="bio-1",
        subject_id="athlete-9",
        subject_secret=_SUBJECT_SECRET,
        data_scope="biometric_raw",
        purposes=("coaching",),
        granted_at=_T0,
        expires_at=_EXP,
    )
    params.update(over)
    return grant_biometric_use(**params)


def _degradation_plan(prev="genesis", **over):
    params = dict(
        plan_id="plan-1",
        system_id="auto-lines",
        failure_modes=("heat_failure", "sensor_failure"),
        takeover_procedure_digest=_PROCEDURE,
        authority_secret=_AUTH_SECRET,
        issued_by="tournament-director",
        tested_at=_T0,
        expires_at=_EXP,
        prev_digest=prev,
    )
    params.update(over)
    return issue_degradation_plan(**params)


def _coach_output(**over):
    params = dict(
        output_digest="44" * 32,
        coach_id="coach-ai-3",
        claimed_capabilities=("technique", "recovery"),
        not_qualified_for=("nutrition_general", "mental_skills"),
        framing="coaching_feedback",
        topic="technique",
    )
    params.update(over)
    return CoachOutput(**params)


class FinalAdjudicationGateTests(unittest.TestCase):
    def test_non_gated_scene_allows_without_countersign(self):
        verdict = final_adjudication_gate(
            [],
            decision_digest=_DECISION,
            scene_class="routine_coaching",
            decision_time=_T0,
            check_time=_T1,
        )
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, "authoritative")

    def test_gated_scene_without_receipt_is_assist_only(self):
        verdict = final_adjudication_gate(
            [],
            decision_digest=_DECISION,
            scene_class="crowded_scene",
            decision_time=_T0,
            check_time=_T1,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_NO_ADJUDICATION, verdict.reason)
        self.assertEqual(verdict.classification, "non_authoritative")
        self.assertTrue(verdict.mandatory_human_review)

    def test_gated_scene_with_valid_countersign_releases(self):
        receipt = _adjudication_receipt()
        verdict = final_adjudication_gate(
            [receipt],
            decision_digest=_DECISION,
            scene_class="crowded_scene",
            decision_time=_T0,
            check_time=_T1,
        )
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, "authoritative")
        self.assertEqual(verdict.receipt_digest, receipt.receipt_digest)

    def test_countersign_predating_decision_denies(self):
        receipt = _adjudication_receipt(adjudicated_at=_T0)
        verdict = final_adjudication_gate(
            [receipt],
            decision_digest=_DECISION,
            scene_class="crowded_scene",
            decision_time=_T1,  # decision happened after the countersign
            check_time=_T1,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("predates", verdict.reason)

    def test_wrong_decision_digest_denies(self):
        receipt = _adjudication_receipt()
        verdict = final_adjudication_gate(
            [receipt],
            decision_digest="55" * 32,  # different decision
            scene_class="crowded_scene",
            decision_time=_T0,
            check_time=_T1,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_NO_ADJUDICATION, verdict.reason)

    def test_expired_countersign_denies(self):
        receipt = _adjudication_receipt()
        verdict = final_adjudication_gate(
            [receipt],
            decision_digest=_DECISION,
            scene_class="crowded_scene",
            decision_time=_T0,
            check_time=_EXP + 1,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("expired", verdict.reason)

    def test_qualified_scene_allows(self):
        receipt = _adjudication_receipt(
            receipt_id="adj-2",
            scene_class="subjective_call",
            qualified_scenes=("subjective_call",),
        )
        verdict = final_adjudication_gate(
            [receipt],
            decision_digest=_DECISION,
            scene_class="subjective_call",
            decision_time=_T0,
            check_time=_T1,
        )
        self.assertTrue(verdict.allowed)

    def test_issuing_for_unqualified_scene_fails_closed(self):
        with self.assertRaises(AdjudicationError):
            _adjudication_receipt(
                receipt_id="adj-3",
                scene_class="medical_advice",
                qualified_scenes=("subjective_call",),
            )

    def test_tampered_chain_denies(self):
        r1 = _adjudication_receipt()
        r2 = _adjudication_receipt(receipt_id="adj-2", prev_digest=r1.receipt_digest)
        broken = _adjudication_receipt(
            receipt_id="adj-3", prev_digest="00" * 64  # chain break
        )
        verdict = final_adjudication_gate(
            [r1, r2, broken],
            decision_digest=_DECISION,
            scene_class="crowded_scene",
            decision_time=_T0,
            check_time=_T1,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("chain", verdict.reason)


class PopulationFitTests(unittest.TestCase):
    def test_population_match_allows(self):
        verdict = check_population_fit(
            [_population_receipt()],
            model_digest=_MODEL,
            capability_id="concussion-assist-v2",
            target_population="adult_male_pro",
            check_time=_T1,
        )
        self.assertTrue(verdict.allowed)
        self.assertFalse(verdict.population_mismatch)

    def test_population_mismatch_flags_non_authoritative(self):
        verdict = check_population_fit(
            [_population_receipt()],
            model_digest=_MODEL,
            capability_id="concussion-assist-v2",
            target_population="youth_athlete",  # male-pro data on youth
            check_time=_T1,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_POPULATION_MISMATCH, verdict.reason)
        self.assertTrue(verdict.population_mismatch)
        self.assertEqual(verdict.classification, "non_authoritative")

    def test_mixed_population_covers_all(self):
        verdict = check_population_fit(
            [_population_receipt(measured_populations=("mixed_population",))],
            model_digest=_MODEL,
            capability_id="concussion-assist-v2",
            target_population="youth_athlete",
            check_time=_T1,
        )
        self.assertTrue(verdict.allowed)

    def test_no_population_receipt_denies(self):
        verdict = check_population_fit(
            [],
            model_digest=_MODEL,
            capability_id="concussion-assist-v2",
            target_population="youth_athlete",
            check_time=_T1,
        )
        self.assertFalse(verdict.allowed)


class BiometricPurposeTests(unittest.TestCase):
    def test_granted_purpose_allows(self):
        verdict = biometric_purpose_binding(
            [_biometric_grant()],
            subject_id="athlete-9",
            data_scope="biometric_raw",
            purpose="coaching",
            check_time=_T1,
        )
        self.assertTrue(verdict.allowed)

    def test_model_training_is_a_new_purpose(self):
        verdict = biometric_purpose_binding(
            [_biometric_grant()],
            subject_id="athlete-9",
            data_scope="biometric_raw",
            purpose="model_training",
            check_time=_T1,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_PURPOSE_CREEP, verdict.reason)

    def test_resale_without_grant_is_hard_deny(self):
        verdict = biometric_purpose_binding(
            [_biometric_grant()],
            subject_id="athlete-9",
            data_scope="biometric_raw",
            purpose="third_party_resale",
            check_time=_T1,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_RESALE, verdict.reason)

    def test_resale_with_explicit_grant_allows(self):
        grant = _biometric_grant(
            resale_allowed=True, purposes=("coaching", "third_party_resale")
        )
        verdict = biometric_purpose_binding(
            [grant],
            subject_id="athlete-9",
            data_scope="biometric_raw",
            purpose="third_party_resale",
            check_time=_T1,
        )
        self.assertTrue(verdict.allowed)

    def test_revoked_grant_denies_at_use_time(self):
        grant = _biometric_grant()
        revoked = revoke_biometric_use(grant, subject_secret=_SUBJECT_SECRET)
        verdict = biometric_purpose_binding(
            [revoked],
            subject_id="athlete-9",
            data_scope="biometric_raw",
            purpose="coaching",
            check_time=_T1,
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("revoked", verdict.reason)


class CoachHonestyTests(unittest.TestCase):
    def test_coach_output_within_label_allows(self):
        verdict = check_coach_output(_coach_output())
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, "authoritative")

    def test_coach_diagnosis_framing_denies_and_redirects(self):
        verdict = check_coach_output(
            _coach_output(framing="medical_diagnosis", topic="knee_pain")
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_COACH_DIAGNOSIS, verdict.reason)
        self.assertIn("clinical", verdict.reason)

    def test_coach_without_honesty_label_is_assist_only(self):
        verdict = check_coach_output(_coach_output(not_qualified_for=()))
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_COACH_LABEL_MISSING, verdict.reason)
        self.assertEqual(verdict.classification, "non_authoritative")

    def test_coach_topic_inside_disclaimed_set_denies(self):
        verdict = check_coach_output(
            _coach_output(topic="nutrition_general")  # disclaimed by its own label
        )
        self.assertFalse(verdict.allowed)
        self.assertIn("unqualified", verdict.reason)


class DegradationAndBettingTests(unittest.TestCase):
    def test_degradation_plan_present_allows_registration(self):
        verdict = check_degradation_plan(
            [_degradation_plan()], system_id="auto-lines", check_time=_T1
        )
        self.assertTrue(verdict.allowed)

    def test_no_degradation_plan_refuses_registration(self):
        verdict = check_degradation_plan([], system_id="auto-lines", check_time=_T1)
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_NO_DEGRADATION_PLAN, verdict.reason)

    def test_betting_input_in_officiating_pipeline_denies(self):
        verdict = check_pipeline_mixing(
            pipeline="officiating",
            inputs=(
                {"source": "officiating", "feed": "trackers"},
                {"source": "betting", "feed": "odds"},
            ),
        )
        self.assertFalse(verdict.allowed)
        self.assertIn(DENY_BETTING_CONTAMINATION, verdict.reason)

    def test_betting_pipeline_itself_is_fine(self):
        verdict = check_pipeline_mixing(
            pipeline="betting",
            inputs=({"source": "betting", "feed": "odds"},),
        )
        self.assertTrue(verdict.allowed)

    def test_schema_version_pinned(self):
        self.assertEqual(ADJUDICATION_SCHEMA_VERSION, "northstar.adjudication.v1")
        receipt = AdjudicationReceipt(
            receipt_id="x",
            decision_digest="00" * 32,
            adjudicator_id="y",
            adjudicator_pubkey_hex="00" * 32,
            qualified_scenes=("crowded_scene",),
            scene_class="crowded_scene",
            adjudicated_at=1,
            expires_at=2,
            issued_by="z",
            authority_pubkey_hex="00" * 32,
            signature_hex="00" * 128,
        )
        self.assertEqual(receipt.schema_version, ADJUDICATION_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
