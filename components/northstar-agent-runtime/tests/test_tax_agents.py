"""Tests for tax_agents (one-hundred-forty-eighth batch)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ed25519 import public_key, sign

from canonical_json import jcs_canonical_json

from tax_agents import (
    AIProposal,
    AnnexIIIPlan,
    AppealBindingRegistry,
    AssessmentSignoffRegistry,
    AuthorityRegistry,
    ExplanationRegistry,
    FlagLead,
    ModelRegistrationRegistry,
    OfficerDecision,
    OfficerOverrideRate,
    PreArrivalScore,
    TrainingDataAuditRegistry,
    ai_proposes_human_disposes,
    annex_iii_clock,
    appeal_window,
    customs_lead_gate,
    explanation_receipt,
    flag_not_fraud_gate,
    human_final_gate,
    selection_bias_probe,
    shadow_ai_registry,
    training_data_audit,
    ANNEX_III_OMNIBUS_EPOCH,
    TaxError,
)

SEC = b"tax-bench-auth-" + b"0" * 17
assert len(SEC) == 32
PUB = public_key(SEC)
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
DAY = 86_400
SCHEMA = "northstar.tax.v1"


def _authorities():
    reg = AuthorityRegistry()
    reg.register("bench-tax-op", PUB.hex())
    return reg


def _flag_sig(flag):
    return sign(SEC, jcs_canonical_json({
        "schema": SCHEMA, "type": "flag_lead",
        "flag_id": flag.flag_id, "subject_id": flag.subject_id,
        "model_id": flag.model_id, "raised_at": flag.raised_at,
        "score": flag.score, "authority_id": flag.authority_id,
    }))


def _signed_flag(raised_at=T0, sig_ok=True):
    flag = FlagLead(
        flag_id="fl-1", subject_id="sub-1", model_id="model-1",
        raised_at=raised_at, score=0.8,
        authority_id="bench-tax-op", authority_pubkey_hex=PUB.hex(),
        signature_hex="00" * 128)
    if sig_ok:
        flag = FlagLead(**{**flag.__dict__, "signature_hex": _flag_sig(flag).hex()})
    return flag


def _score_sig(score):
    return sign(SEC, jcs_canonical_json({
        "schema": SCHEMA, "type": "prearrival_score",
        "consignment_id": score.consignment_id, "model_id": score.model_id,
        "score": score.score, "scored_at": score.scored_at,
        "authority_id": score.authority_id,
    }))


def _signed_score(scored_at=T0):
    score = PreArrivalScore(
        consignment_id="con-1", model_id="model-1", score=0.75,
        scored_at=scored_at, authority_id="bench-tax-op",
        authority_pubkey_hex=PUB.hex(), signature_hex="00" * 128)
    return PreArrivalScore(**{**score.__dict__, "signature_hex": _score_sig(score).hex()})


def _proposal_sig(p):
    return sign(SEC, jcs_canonical_json({
        "schema": SCHEMA, "type": "ai_proposal",
        "proposal_id": p.proposal_id, "recommended_action": p.recommended_action,
        "proposed_at": p.proposed_at, "model_id": p.model_id,
        "authority_id": p.authority_id,
    }))


def _decision_sig(d):
    return sign(SEC, jcs_canonical_json({
        "schema": SCHEMA, "type": "officer_decision",
        "proposal_id": d.proposal_id, "officer_id": d.officer_id,
        "decision": d.decision, "decided_at": d.decided_at,
        "reviewed_evidence_digest": d.reviewed_evidence_digest,
        "authority_id": d.authority_id,
    }))


def _signed_proposal():
    p = AIProposal(
        proposal_id="pr-1", recommended_action="hold_for_inspection",
        proposed_at=T0, model_id="model-1", authority_id="bench-tax-op",
        authority_pubkey_hex=PUB.hex(), signature_hex="00" * 128)
    return AIProposal(**{**p.__dict__, "signature_hex": _proposal_sig(p).hex()})


def _signed_decision(decision="modify", decided_at=T0 + 100):
    d = OfficerDecision(
        proposal_id="pr-1", officer_id="officer-lin", decision=decision,
        decided_at=decided_at, reviewed_evidence_digest=HEX64,
        authority_id="bench-tax-op", authority_pubkey_hex=PUB.hex(),
        signature_hex="00" * 128)
    return OfficerDecision(**{**d.__dict__, "signature_hex": _decision_sig(d).hex()})


def _plan_sig(p):
    return sign(SEC, jcs_canonical_json({
        "schema": SCHEMA, "type": "annex_iii_plan",
        "jurisdiction": p.jurisdiction, "posture": p.posture,
        "target_at": p.target_at, "milestones_completed": p.milestones_completed,
        "total_milestones": p.total_milestones, "authority_id": p.authority_id,
    }))


def _signed_plan(posture="voluntary_alignment", target_at=ANNEX_III_OMNIBUS_EPOCH):
    p = AnnexIIIPlan(
        jurisdiction="bench-eu-state", posture=posture, target_at=target_at,
        milestones_completed=3, total_milestones=6,
        authority_id="bench-tax-op", authority_pubkey_hex=PUB.hex(),
        signature_hex="00" * 128)
    return AnnexIIIPlan(**{**p.__dict__, "signature_hex": _plan_sig(p).hex()})


def _register_training_data(model_id="model-1", receipt_id="td-1", issued_at=T0):
    reg = TrainingDataAuditRegistry(_authorities())
    payload = {
        "schema": SCHEMA, "type": "training_data_audit",
        "receipt_id": receipt_id, "model_id": model_id,
        "historical_audit_slice_id": "slice-2024", "debias_digest": HEX64,
        "auditor_id": "aud-kim", "issued_at": issued_at,
        "authority_id": "bench-tax-op", "authority_pubkey_hex": PUB.hex(),
        "signature_hex": "00" * 64, "prev_digest": "genesis",
    }
    reg.issue(receipt_id, model_id, "slice-2024", HEX64, "aud-kim", issued_at,
              "bench-tax-op", sign(SEC, jcs_canonical_json(payload)))
    return reg


def _register_signoff(assessment_id="assess-1", human_id="officer-lin", signed_at=T0):
    reg = AssessmentSignoffRegistry(_authorities())
    payload = {
        "schema": SCHEMA, "type": "assessment_signoff",
        "receipt_id": "so-1", "assessment_id": assessment_id,
        "assessment_digest": HEX64, "human_id": human_id,
        "signed_at": signed_at, "authority_id": "bench-tax-op",
        "authority_pubkey_hex": PUB.hex(), "signature_hex": "00" * 64,
        "prev_digest": "genesis",
    }
    reg.issue("so-1", assessment_id, HEX64, human_id, signed_at, "bench-tax-op",
              sign(SEC, jcs_canonical_json(payload)))
    return reg


def _register_appeal(assessment_id="assess-1", receipt_id="ab-1", deadline=T0 + 45 * DAY):
    reg = AppealBindingRegistry(_authorities())
    payload = {
        "schema": SCHEMA, "type": "appeal_binding",
        "receipt_id": receipt_id, "assessment_id": assessment_id,
        "channel_id": "tax-tribunal", "opened_at": T0, "deadline": deadline,
        "authority_id": "bench-tax-op", "authority_pubkey_hex": PUB.hex(),
        "signature_hex": "00" * 64, "prev_digest": "genesis",
    }
    reg.issue(receipt_id, assessment_id, "tax-tribunal", T0, deadline,
              "bench-tax-op", sign(SEC, jcs_canonical_json(payload)))
    return reg


def _register_model(model_id="model-1", digest=HEX64, receipt_id="mr-1"):
    reg = ModelRegistrationRegistry(_authorities())
    payload = {
        "schema": SCHEMA, "type": "model_registration",
        "receipt_id": receipt_id, "model_id": model_id,
        "model_digest": digest, "jurisdiction": "bench-eu-state",
        "registered_at": T0, "authority_id": "bench-tax-op",
        "authority_pubkey_hex": PUB.hex(), "signature_hex": "00" * 64,
        "prev_digest": "genesis",
    }
    reg.issue(receipt_id, model_id, digest, "bench-eu-state", T0, "bench-tax-op",
              sign(SEC, jcs_canonical_json(payload)))
    return reg


class TestFlagNotFraud(unittest.TestCase):
    def test_lead_action_allowed(self):
        v = flag_not_fraud_gate(_signed_flag(), "queue_review", T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_auto_fraud_accusation_denied(self):
        v = flag_not_fraud_gate(_signed_flag(), "accuse_fraud", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("auto_fraud_accusation", v.reason)

    def test_auto_penalty_denied(self):
        v = flag_not_fraud_gate(_signed_flag(), "assess_penalty", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("auto_fraud_accusation", v.reason)

    def test_stale_flag_denied(self):
        v = flag_not_fraud_gate(_signed_flag(raised_at=T0 - 200 * DAY),
                                "queue_review", T0)
        self.assertFalse(v.allowed)
        self.assertIn("stale_flag", v.reason)

    def test_bad_sig_denied(self):
        v = flag_not_fraud_gate(_signed_flag(sig_ok=False), "queue_review", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("sig_invalid", v.reason)

    def test_bad_struct_raises(self):
        with self.assertRaises(TaxError):
            flag_not_fraud_gate("not-a-flag", "queue_review", T0)


class TestSelectionBias(unittest.TestCase):
    def test_clean_features_allowed(self):
        v = selection_bias_probe(["income_variance", "deduction_ratio"], [0.10, 0.12], T0)
        self.assertTrue(v.allowed)

    def test_nationality_banned_denied(self):
        v = selection_bias_probe(["income_variance", "nationality"], [0.10, 0.12], T0)
        self.assertFalse(v.allowed)
        self.assertIn("banned_feature", v.reason)

    def test_zip_code_banned_denied(self):
        v = selection_bias_probe(["zip_code"], [0.10], T0)
        self.assertFalse(v.allowed)
        self.assertIn("banned_feature", v.reason)

    def test_disparate_impact_denied(self):
        v = selection_bias_probe(["income_variance"], [0.05, 0.30], T0)
        self.assertFalse(v.allowed)
        self.assertIn("disparate_impact", v.reason)


class TestTrainingDataAudit(unittest.TestCase):
    def test_live_audit_allowed(self):
        reg = _register_training_data()
        v = training_data_audit(reg, "model-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_missing_audit_denied(self):
        reg = TrainingDataAuditRegistry(_authorities())
        v = training_data_audit(reg, "ghost-model", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_training_audit", v.reason)

    def test_stale_audit_denied(self):
        reg = _register_training_data(model_id="model-2", receipt_id="td-2")
        v = training_data_audit(reg, "model-2", T0 + 400 * DAY)
        self.assertFalse(v.allowed)
        self.assertIn("stale_training_audit", v.reason)


class TestHumanFinal(unittest.TestCase):
    def test_unsigned_assessment_denied(self):
        reg = AssessmentSignoffRegistry(_authorities())
        v = human_final_gate(reg, "assess-1", T0)
        self.assertFalse(v.allowed)
        self.assertIn("unsigned_assessment", v.reason)

    def test_signed_assessment_allowed(self):
        reg = _register_signoff()
        v = human_final_gate(reg, "assess-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_rubber_stamp_denied(self):
        reg = _register_signoff()
        rates = {"officer-lin": OfficerOverrideRate("officer-lin", 200, 2)}
        v = human_final_gate(reg, "assess-1", T0 + 10, rates)
        self.assertFalse(v.allowed)
        self.assertIn("rubber_stamp", v.reason)


class TestAppealWindow(unittest.TestCase):
    def test_bound_window_allowed(self):
        reg = _register_appeal()
        v = appeal_window(reg, "assess-1", T0 + DAY)
        self.assertTrue(v.allowed)

    def test_missing_binding_denied(self):
        reg = AppealBindingRegistry(_authorities())
        v = appeal_window(reg, "assess-ghost", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_appeal_path", v.reason)

    def test_enforcement_while_open_denied(self):
        reg = _register_appeal(assessment_id="assess-2", receipt_id="ab-2")
        v = appeal_window(reg, "assess-2", T0 + DAY, enforcing=True)
        self.assertFalse(v.allowed)
        self.assertIn("appeal_window_open", v.reason)


class TestExplanation(unittest.TestCase):
    def test_missing_explanation_denied(self):
        reg = ExplanationRegistry(_authorities())
        v = explanation_receipt(reg, "sel-ghost", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_explanation", v.reason)


class TestShadowAI(unittest.TestCase):
    def test_unregistered_denied(self):
        reg = ModelRegistrationRegistry(_authorities())
        v = shadow_ai_registry(reg, "ghost-model", HEX64, T0)
        self.assertFalse(v.allowed)
        self.assertIn("shadow_ai", v.reason)

    def test_digest_swap_denied(self):
        reg = _register_model()
        v = shadow_ai_registry(reg, "model-1", HEX64_B, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("shadow_ai", v.reason)

    def test_registered_allowed(self):
        reg = _register_model()
        v = shadow_ai_registry(reg, "model-1", HEX64, T0 + 10)
        self.assertTrue(v.allowed)


class TestAnnexIIIClock(unittest.TestCase):
    def test_clock_running_allowed(self):
        v = annex_iii_clock(_signed_plan(), T0)
        self.assertTrue(v.allowed)

    def test_excluded_no_plan_denied(self):
        v = annex_iii_clock(_signed_plan(posture="excluded_no_plan"), T0)
        self.assertFalse(v.allowed)
        self.assertIn("annex_iii_excluded", v.reason)

    def test_overdue_denied(self):
        v = annex_iii_clock(
            _signed_plan(target_at=ANNEX_III_OMNIBUS_EPOCH - 1),
            ANNEX_III_OMNIBUS_EPOCH + DAY)
        self.assertFalse(v.allowed)
        self.assertIn("annex_iii_overdue", v.reason)


class TestCustomsLead(unittest.TestCase):
    def test_hold_for_inspection_allowed(self):
        v = customs_lead_gate(_signed_score(), "hold_for_inspection", T0 + 100,
                              officer_id="officer-lin")
        self.assertTrue(v.allowed)

    def test_auto_seize_denied(self):
        v = customs_lead_gate(_signed_score(), "seize", T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("customs_auto_seizure", v.reason)

    def test_hold_unassigned_denied(self):
        v = customs_lead_gate(_signed_score(), "hold_for_inspection", T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("customs_hold_unassigned", v.reason)

    def test_stale_score_denied(self):
        v = customs_lead_gate(_signed_score(scored_at=T0 - 60 * 3600),
                              "release", T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("customs_score_stale", v.reason)


class TestAIProposesHumanDisposes(unittest.TestCase):
    def test_officer_decision_allowed(self):
        v = ai_proposes_human_disposes(_signed_proposal(), _signed_decision())
        self.assertTrue(v.allowed)

    def test_no_decision_denied(self):
        v = ai_proposes_human_disposes(_signed_proposal(), None)
        self.assertFalse(v.allowed)
        self.assertIn("no_officer_decision", v.reason)

    def test_rubber_stamp_denied(self):
        rates = {"officer-lin": OfficerOverrideRate("officer-lin", 300, 3)}
        v = ai_proposes_human_disposes(_signed_proposal(), _signed_decision(), rates)
        self.assertFalse(v.allowed)
        self.assertIn("rubber_stamp", v.reason)


if __name__ == "__main__":
    unittest.main()
