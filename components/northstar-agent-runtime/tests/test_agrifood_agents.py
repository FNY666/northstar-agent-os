"""Tests for agrifood_agents (one-hundred-fifty-fourth batch)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519
from canonical_json import jcs_canonical_json

from agrifood_agents import (
    AgrifoodError,
    AgrifoodVerdict,
    AssessmentRegistry,
    AssessmentReceipt,
    AuthorityRegistry,
    ConsequenceLogRegistry,
    ConsequenceLogEntry,
    PrescriptionRegistry,
    PrescriptionReceipt,
    DataAuthRegistry,
    DataAuthReceipt,
    DomainRegistry,
    DomainStatement,
    ReadinessRegistry,
    ReadinessReceipt,
    EnvelopeRegistry,
    EnvelopeReceipt,
    TraceRegistry,
    TraceEntry,
    assessment_claim_receipt,
    physical_consequence_log,
    prescription_human_final_gate,
    data_authorization_receipt,
    applicability_domain_statement,
    offline_fallback_mode,
    capability_envelope_gate,
    traceability_chain,
    CLASS_AUTHORITATIVE,
    CLASS_NON_AUTHORITATIVE,
    PRESCRIPTION_DEVIATION_MAX,
)

SEC = b"\x0a" * 32
PUB = ed25519.public_key(SEC).hex()
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
HEX64_C = "ef" * 32
HEX64_D = "01" * 32


def _authorities():
    reg = AuthorityRegistry()
    reg.register("bench-op", PUB)
    return reg


def _sign(payload):
    return ed25519.sign(SEC, jcs_canonical_json(payload))


def _prev(log):
    return log[-1].receipt_digest if log else "genesis"


# --- issuance helpers -------------------------------------------------------


def _assess(reg, rid, aid, reviewed_at=T0):
    r = AssessmentReceipt(
        receipt_id=rid, assessment_id=aid, claim_id="claim-1",
        model_version="fasal-v9", input_digest=HEX64, confidence_bps=8200,
        human_reviewer_id="rev-chen", reviewed_at=reviewed_at,
        authority_id="bench-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, prev_digest=_prev(reg.log))
    return reg.issue(rid, aid, "claim-1", "fasal-v9", HEX64, 8200,
                     "rev-chen", reviewed_at, "bench-op", _sign(r._payload()))


def _conseq(reg, rid, aid, kind="pesticide_spray"):
    r = ConsequenceLogEntry(
        receipt_id=rid, action_id=aid, action_kind=kind,
        model_version="spray-v3", input_digest=HEX64_B, decided_at=T0,
        authority_id="bench-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, prev_digest=_prev(reg.log))
    return reg.issue(rid, aid, kind, "spray-v3", HEX64_B, T0, "bench-op",
                     _sign(r._payload()))


def _presc(reg, rid, pid, prescribed, regional, approver="", approved_at=T0):
    r = PrescriptionReceipt(
        receipt_id=rid, prescription_id=pid, field_id="field-1",
        input_kind="nitrogen_kg_ha", prescribed_value=prescribed,
        regional_recommendation=regional, approver_id=approver,
        approved_at=approved_at, authority_id="bench-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        prev_digest=_prev(reg.log))
    return reg.issue(rid, pid, "field-1", "nitrogen_kg_ha", prescribed,
                     regional, approver, approved_at, "bench-op",
                     _sign(r._payload()))


def _auth(reg, rid, scope="soil.moisture", purpose="irrigation_advice",
          valid_from=T0, expires_at=T0 + 86400):
    r = DataAuthReceipt(
        receipt_id=rid, farm_id="farm-1", principal_id="agent-1",
        scope=scope, purpose=purpose, valid_from=valid_from,
        expires_at=expires_at, authority_id="bench-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        prev_digest=_prev(reg.log))
    return reg.issue(rid, "farm-1", "agent-1", scope, purpose, valid_from,
                     expires_at, "bench-op", _sign(r._payload()))


def _domain(reg, rid, model="yield-eu-v2",
            regions=("EU", "US-midwest"), patterns=("monoculture-irrigated",)):
    r = DomainStatement(
        receipt_id=rid, statement_id="ds-1", model_id=model,
        covered_regions=regions, covered_patterns=patterns,
        authority_id="bench-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, prev_digest=_prev(reg.log))
    return reg.issue(rid, "ds-1", model, list(regions), list(patterns),
                     "bench-op", _sign(r._payload()))


def _ready(reg, rid, dep="dep-1", offline=True, langs=("sw", "pt",)):
    r = ReadinessReceipt(
        receipt_id=rid, deployment_id=dep, supports_offline=offline,
        local_languages=langs, offline_guidance_digest=HEX64_C,
        authority_id="bench-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, prev_digest=_prev(reg.log))
    return reg.issue(rid, dep, offline, list(langs), HEX64_C, "bench-op",
                     _sign(r._payload()))


def _envelope(reg, rid, robot="robot-1", issued_at=T0,
              slope=10.0, moisture=0.5, obstacles=0.3, speed=2.0):
    r = EnvelopeReceipt(
        receipt_id=rid, envelope_id="env-1", robot_id=robot,
        max_slope_deg=slope, max_soil_moisture=moisture,
        max_obstacle_density=obstacles, max_speed_ms=speed,
        issued_at=issued_at, authority_id="bench-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        prev_digest=_prev(reg.log))
    return reg.issue(rid, "env-1", robot, slope, moisture, obstacles, speed,
                     issued_at, "bench-op", _sign(r._payload()))


def _trace(reg, rid, lot, stage, digest=HEX64_D):
    r = TraceEntry(
        receipt_id=rid, lot_id=lot, stage=stage, record_digest=digest,
        recorded_at=T0, authority_id="bench-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, prev_digest=_prev(reg.log))
    return reg.issue(rid, lot, stage, digest, T0, "bench-op", _sign(r._payload()))


class TestAssessmentReceipts(unittest.TestCase):
    def test_fresh_reviewed_assessment_allowed(self):
        reg = AssessmentRegistry(_authorities())
        _assess(reg, "as-1", "a-1")
        v = assessment_claim_receipt(reg, "a-1", T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_AUTHORITATIVE)
        self.assertTrue(v.receipt_digest)

    def test_unreceipted_assessment_denied(self):
        reg = AssessmentRegistry(_authorities())
        v = assessment_claim_receipt(reg, "ghost", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("unreceipted_assessment", v.reason)

    def test_stale_review_denied(self):
        reg = AssessmentRegistry(_authorities())
        _assess(reg, "as-1", "a-1", reviewed_at=T0 - 91 * 86400)
        v = assessment_claim_receipt(reg, "a-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("stale_assessment", v.reason)

    def test_verdict_shape_on_failure(self):
        reg = AssessmentRegistry(_authorities())
        v = assessment_claim_receipt(reg, "ghost", T0)
        self.assertIsInstance(v, AgrifoodVerdict)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)


class TestConsequenceLog(unittest.TestCase):
    def test_logged_action_allowed(self):
        reg = ConsequenceLogRegistry(_authorities())
        _conseq(reg, "cl-1", "act-1")
        v = physical_consequence_log(reg, "act-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_unlogged_action_denied(self):
        reg = ConsequenceLogRegistry(_authorities())
        v = physical_consequence_log(reg, "act-ghost", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("no_consequence_log", v.reason)


class TestPrescriptionGate(unittest.TestCase):
    def test_in_band_prescription_allowed_without_approval(self):
        reg = PrescriptionRegistry(_authorities())
        _presc(reg, "px-1", "p-1", prescribed=110.0, regional=100.0)
        v = prescription_human_final_gate(reg, "p-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_out_of_band_with_approval_allowed(self):
        reg = PrescriptionRegistry(_authorities())
        _presc(reg, "px-1", "p-1", prescribed=145.0, regional=100.0,
               approver="agro-li", approved_at=T0)
        v = prescription_human_final_gate(reg, "p-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_out_of_band_without_approval_denied(self):
        reg = PrescriptionRegistry(_authorities())
        _presc(reg, "px-1", "p-1", prescribed=145.0, regional=100.0)
        v = prescription_human_final_gate(reg, "p-1", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("unapproved_prescription", v.reason)

    def test_boundary_exactly_30pct_allowed(self):
        reg = PrescriptionRegistry(_authorities())
        _presc(reg, "px-1", "p-1", prescribed=130.0, regional=100.0)
        v = prescription_human_final_gate(reg, "p-1", T0 + 10)
        self.assertTrue(v.allowed)

    def test_deviation_constant_is_30pct(self):
        self.assertEqual(PRESCRIPTION_DEVIATION_MAX, 0.30)


class TestDataAuth(unittest.TestCase):
    def test_scoped_purpose_bound_read_allowed(self):
        reg = DataAuthRegistry(_authorities())
        _auth(reg, "da-1")
        v = data_authorization_receipt(reg, "farm-1", "agent-1",
                                       "soil.moisture", "irrigation_advice",
                                       T0 + 10)
        self.assertTrue(v.allowed)

    def test_prefix_scope_covers_child(self):
        reg = DataAuthRegistry(_authorities())
        _auth(reg, "da-1", scope="soil")
        v = data_authorization_receipt(reg, "farm-1", "agent-1",
                                       "soil.moisture", "irrigation_advice",
                                       T0 + 10)
        self.assertTrue(v.allowed)

    def test_out_of_scope_read_denied(self):
        reg = DataAuthRegistry(_authorities())
        _auth(reg, "da-1", scope="soil.moisture")
        v = data_authorization_receipt(reg, "farm-1", "agent-1",
                                       "yield.history", "irrigation_advice",
                                       T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("unauthorized_access", v.reason)

    def test_purpose_mismatch_denied(self):
        reg = DataAuthRegistry(_authorities())
        _auth(reg, "da-1")
        v = data_authorization_receipt(reg, "farm-1", "agent-1",
                                       "soil.moisture", "credit_scoring",
                                       T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("unauthorized_access", v.reason)

    def test_expired_authorization_denied(self):
        reg = DataAuthRegistry(_authorities())
        _auth(reg, "da-1", valid_from=T0 - 100, expires_at=T0 - 1)
        v = data_authorization_receipt(reg, "farm-1", "agent-1",
                                       "soil.moisture", "irrigation_advice",
                                       T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("unauthorized_access", v.reason)

    def test_overlong_ttl_raises(self):
        reg = DataAuthRegistry(_authorities())
        with self.assertRaises(AgrifoodError):
            _auth(reg, "da-1", valid_from=T0, expires_at=T0 + 400 * 86400)


class TestDomainStatement(unittest.TestCase):
    def test_in_domain_allowed(self):
        reg = DomainRegistry(_authorities())
        _domain(reg, "d-1")
        v = applicability_domain_statement(reg, "yield-eu-v2", "EU",
                                           "monoculture-irrigated", T0 + 10)
        self.assertTrue(v.allowed)

    def test_out_of_region_denied(self):
        reg = DomainRegistry(_authorities())
        _domain(reg, "d-1")
        v = applicability_domain_statement(reg, "yield-eu-v2", "KE-smallholder",
                                           "monoculture-irrigated", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("out_of_domain", v.reason)

    def test_out_of_pattern_denied(self):
        reg = DomainRegistry(_authorities())
        _domain(reg, "d-1")
        v = applicability_domain_statement(reg, "yield-eu-v2", "EU",
                                           "smallholder-mixed-rainfed", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("out_of_domain", v.reason)

    def test_no_statement_denied(self):
        reg = DomainRegistry(_authorities())
        v = applicability_domain_statement(reg, "ghost-model", "EU",
                                           "monoculture-irrigated", T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_domain_statement", v.reason)


class TestOfflineFallback(unittest.TestCase):
    def test_online_allowed(self):
        reg = ReadinessRegistry(_authorities())
        _ready(reg, "rd-1")
        v = offline_fallback_mode(reg, "dep-1", True, "sw", T0 + 10)
        self.assertTrue(v.allowed)

    def test_offline_with_fallback_allowed(self):
        reg = ReadinessRegistry(_authorities())
        _ready(reg, "rd-1", langs=("sw", "pt"))
        v = offline_fallback_mode(reg, "dep-1", False, "sw", T0 + 10)
        self.assertTrue(v.allowed)

    def test_offline_no_fallback_denied(self):
        reg = ReadinessRegistry(_authorities())
        _ready(reg, "rd-1", offline=False)
        v = offline_fallback_mode(reg, "dep-1", False, "sw", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("silent_failure", v.reason)

    def test_offline_missing_language_denied(self):
        reg = ReadinessRegistry(_authorities())
        _ready(reg, "rd-1", langs=("pt",))
        v = offline_fallback_mode(reg, "dep-1", False, "sw", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("silent_failure", v.reason)


class TestEnvelopeGate(unittest.TestCase):
    def test_in_envelope_allowed(self):
        reg = EnvelopeRegistry(_authorities())
        _envelope(reg, "e-1")
        v = capability_envelope_gate(reg, "robot-1", {
            "soil_moisture": 0.4, "slope_deg": 5.0,
            "obstacle_density": 0.2, "speed_ms": 1.5}, T0 + 10)
        self.assertTrue(v.allowed)

    def test_breach_refused(self):
        reg = EnvelopeRegistry(_authorities())
        _envelope(reg, "e-1")
        v = capability_envelope_gate(reg, "robot-1", {
            "soil_moisture": 0.95, "slope_deg": 5.0,
            "obstacle_density": 0.2, "speed_ms": 1.5}, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("envelope_breach", v.reason)

    def test_no_envelope_denied(self):
        reg = EnvelopeRegistry(_authorities())
        v = capability_envelope_gate(reg, "ghost-robot", {
            "soil_moisture": 0.1, "slope_deg": 1.0,
            "obstacle_density": 0.1, "speed_ms": 1.0}, T0)
        self.assertFalse(v.allowed)
        self.assertIn("no_envelope", v.reason)

    def test_stale_envelope_denied(self):
        reg = EnvelopeRegistry(_authorities())
        _envelope(reg, "e-1", issued_at=T0 - 31 * 86400)
        v = capability_envelope_gate(reg, "robot-1", {
            "soil_moisture": 0.1, "slope_deg": 1.0,
            "obstacle_density": 0.1, "speed_ms": 1.0}, T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("stale_envelope", v.reason)


class TestTraceability(unittest.TestCase):
    def _full_chain(self, reg, lot="lot-1"):
        _trace(reg, "t-1", lot, "sensor")
        _trace(reg, "t-2", lot, "decision", HEX64)
        _trace(reg, "t-3", lot, "application", HEX64_B)
        _trace(reg, "t-4", lot, "provenance", HEX64_C)

    def test_complete_chain_allowed(self):
        reg = TraceRegistry(_authorities())
        self._full_chain(reg)
        v = traceability_chain(reg, "lot-1", T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_AUTHORITATIVE)

    def test_missing_stage_denied(self):
        reg = TraceRegistry(_authorities())
        _trace(reg, "t-1", "lot-2", "sensor")
        _trace(reg, "t-2", "lot-2", "decision", HEX64)
        _trace(reg, "t-3", "lot-2", "provenance", HEX64_C)
        v = traceability_chain(reg, "lot-2", T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("traceability_breach", v.reason)

    def test_empty_lot_denied(self):
        reg = TraceRegistry(_authorities())
        v = traceability_chain(reg, "lot-ghost", T0)
        self.assertFalse(v.allowed)
        self.assertIn("traceability_breach", v.reason)

    def test_bad_stage_raises(self):
        reg = TraceRegistry(_authorities())
        with self.assertRaises(AgrifoodError):
            _trace(reg, "t-1", "lot-1", "laundering")


if __name__ == "__main__":
    unittest.main()
