"""Tests for env_cost.py (one-hundred-fifteenth batch): environmental-cost
receipts, curtailment, confidence-gated detection, maturity labels,
physics gate, detect->action linkage, efficiency claims."""

import unittest

from canonical_json import jcs_sha256_hex
from dual_use import AuthorityRegistry as DualRegistry
from dual_use import (
    _binding_digest_for_signing,
    authority_keypair as dual_authority_keypair,
    issue_constraint_binding,
    sign_binding_digest,
)
from env_cost import (
    DETECTION_CONFIDENCE_MIN,
    DENY_BUDGET_EXHAUSTED,
    DENY_CURTAILMENT_VIOLATION,
    DENY_INSUFFICIENT_CONFIDENCE,
    DENY_PHYSICS_GAP,
    DENY_UNKNOWN_BUDGET,
    DENY_UNVERIFIABLE_EFFICIENCY,
    ActionLinker,
    AuthorityRegistry,
    DetectionRegistry,
    EfficiencyClaimRegistry,
    EnvCostError,
    EnvironmentalCostLedger,
    MaturityRegistry,
    PhysicsGate,
    authority_keypair,
    carbon_kg_est,
    curtailment_digest_for_signing,
    issue_curtailment,
    issue_env_profile,
    profile_digest_for_signing,
    sign_digest,
)

_T0 = 1_789_000_000
_FACTOR = "0.429"
_FACTOR_DIGEST = jcs_sha256_hex({"emission-factor": "PJM-2026-marginal"})
_HEX = jcs_sha256_hex({"x": 1})


def _registry():
    pub, seed = authority_keypair(b"\x0f" * 32)
    return AuthorityRegistry({"grid-authority": pub}), seed


def _profile_kwargs(budget_id="b1", **over):
    kw = dict(
        budget_id=budget_id,
        kwh_total=10_000,
        baseline_kwh_per_hour=100,
        grid_region="PJM",
        emission_factor_digest=_FACTOR_DIGEST,
        emission_factor_kg_per_kwh=_FACTOR,
        issued_by="grid-authority",
        issued_at=_T0,
        expires_at=_T0 + 86_400,
        prev_hash="",
    )
    kw.update(over)
    return kw


def _issue_profile(registry, seed, budget_id="b1", **over):
    kw = _profile_kwargs(budget_id, **over)
    digest = profile_digest_for_signing(**kw)
    return issue_env_profile(registry, signature=sign_digest(seed, digest), **kw)


def _curtail_kwargs(**over):
    kw = dict(
        curtailment_id="c1",
        grid_region="PJM",
        start_unix=_T0,
        end_unix=_T0 + 3_600,
        reduction_factor_permille=300,
        issued_by="grid-authority",
        issued_at=_T0,
        prev_hash="",
    )
    kw.update(over)
    return kw


def _issue_curtailment(registry, seed, **over):
    kw = _curtail_kwargs(**over)
    digest = curtailment_digest_for_signing(**kw)
    return issue_curtailment(registry, signature=sign_digest(seed, digest), **kw)


def _ledger_with_profile(registry, seed):
    ledger = EnvironmentalCostLedger()
    ledger.register_profile(_issue_profile(registry, seed))
    return ledger


def _physics_gate():
    pub, seed = dual_authority_keypair(b"\x0f" * 32)
    registry = DualRegistry({"lab-director": pub})
    list_digest = jcs_sha256_hex({"constraints": ["navier-stokes", "mass-balance"]})
    digest = _binding_digest_for_signing(
        task_id="coast-sim", constraint_list_digest=list_digest,
        constraint_source="physics-handbook-v2", issued_by="lab-director",
        issued_at=_T0, prev_hash="")
    binding = issue_constraint_binding(
        registry, task_id="coast-sim", constraint_list_digest=list_digest,
        constraint_source="physics-handbook-v2", issued_by="lab-director",
        issued_at=_T0, signature=sign_binding_digest(seed, digest), prev_hash="")
    gate = PhysicsGate()
    gate.register(binding)
    return gate, list_digest


class ProfileTests(unittest.TestCase):
    def test_issue_ok(self):
        registry, seed = _registry()
        profile = _issue_profile(registry, seed)
        self.assertEqual(profile.budget_id, "b1")
        self.assertEqual(profile.profile_digest,
                         profile_digest_for_signing(**_profile_kwargs()))

    def test_bad_signature_refused(self):
        registry, _seed = _registry()
        with self.assertRaises(EnvCostError):
            issue_env_profile(registry, signature=b"\x00" * 64,
                              **_profile_kwargs())

    def test_unknown_authority_refused(self):
        registry, seed = _registry()
        kw = _profile_kwargs(issued_by="nobody")
        digest = profile_digest_for_signing(**kw)
        with self.assertRaises(EnvCostError):
            issue_env_profile(registry, signature=sign_digest(seed, digest), **kw)

    def test_carbon_is_decimal_and_estimated(self):
        self.assertEqual(carbon_kg_est(100, "0.429"), "42.900")
        self.assertEqual(carbon_kg_est(1, "0.1"), "0.100")


class SpendTests(unittest.TestCase):
    def test_spend_ok_carries_env_fields(self):
        registry, seed = _registry()
        ledger = _ledger_with_profile(registry, seed)
        v = ledger.spend("b1", kwh=100, water_liters=500, purpose="train",
                         created_unix=_T0 + 10)
        self.assertTrue(v.allowed)
        self.assertEqual(v.audit_event["event"], "env.spend")
        self.assertEqual(ledger.remaining_kwh("b1"), 9_900)
        ok, reason = ledger.verify_chain("b1")
        self.assertTrue(ok, reason)

    def test_spend_no_profile_denies(self):
        ledger = EnvironmentalCostLedger()
        v = ledger.spend("nope", kwh=1, water_liters=0, purpose="x",
                         created_unix=_T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNKNOWN_BUDGET, v.reason)

    def test_spend_exhausted_denies(self):
        registry, seed = _registry()
        ledger = _ledger_with_profile(registry, seed)
        ledger.spend("b1", kwh=10_000, water_liters=0, purpose="train",
                     created_unix=_T0 + 1)
        v = ledger.spend("b1", kwh=1, water_liters=0, purpose="train",
                         created_unix=_T0 + 2)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_BUDGET_EXHAUSTED, v.reason)
        self.assertEqual(v.audit_event["event"], "env.budget_exhausted")

    def test_spend_missing_purpose_denies(self):
        registry, seed = _registry()
        ledger = _ledger_with_profile(registry, seed)
        v = ledger.spend("b1", kwh=1, water_liters=0, purpose="",
                         created_unix=_T0)
        self.assertFalse(v.allowed)

    def test_spend_nonpositive_kwh_denies(self):
        registry, seed = _registry()
        ledger = _ledger_with_profile(registry, seed)
        v = ledger.spend("b1", kwh=0, water_liters=0, purpose="x",
                         created_unix=_T0)
        self.assertFalse(v.allowed)

    def test_cost_ledger_aggregation(self):
        registry, seed = _registry()
        ledger = _ledger_with_profile(registry, seed)
        ledger.spend("b1", kwh=100, water_liters=200, purpose="train",
                     created_unix=_T0 + 1)
        ledger.spend("b1", kwh=50, water_liters=100, purpose="train",
                     created_unix=_T0 + 2)
        agg = ledger.cost_ledger("b1")
        self.assertEqual(agg["total_kwh"], 150)
        self.assertEqual(agg["total_water_liters"], 300)
        self.assertEqual(agg["total_carbon_kg_est"], "64.350")
        self.assertEqual(agg["by_purpose"]["train"]["kwh"], 150)


class CurtailmentTests(unittest.TestCase):
    def test_violation_denies(self):
        registry, seed = _registry()
        ledger = _ledger_with_profile(registry, seed)
        ledger.register_curtailment(_issue_curtailment(registry, seed))
        # baseline 100 kwh/h * 300/1000 = 30 cap; 100 exceeds it.
        v = ledger.spend("b1", kwh=100, water_liters=0, purpose="train",
                         created_unix=_T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_CURTAILMENT_VIOLATION, v.reason)
        self.assertEqual(v.audit_event["curtailment_cap_kwh"], 30)

    def test_within_cap_allows(self):
        registry, seed = _registry()
        ledger = _ledger_with_profile(registry, seed)
        ledger.register_curtailment(_issue_curtailment(registry, seed))
        v = ledger.spend("b1", kwh=30, water_liters=0, purpose="train",
                         created_unix=_T0 + 100)
        self.assertTrue(v.allowed)

    def test_outside_window_no_cap(self):
        registry, seed = _registry()
        ledger = _ledger_with_profile(registry, seed)
        ledger.register_curtailment(_issue_curtailment(registry, seed))
        v = ledger.spend("b1", kwh=100, water_liters=0, purpose="train",
                         created_unix=_T0 + 7_200)
        self.assertTrue(v.allowed)


class DetectionTests(unittest.TestCase):
    def test_high_confidence_authorizes(self):
        reg = DetectionRegistry()
        claim, v = reg.detection_receipt(
            detection_id="d1", claim_digest=_HEX, confidence=0.92,
            fit_evidence_digest=_HEX, detector_id="mapl-emit-1",
            detected_unix=_T0)
        self.assertTrue(v.allowed)
        self.assertTrue(claim.usable_as_evidence)
        v2 = reg.authorize_action_on_detection("d1", _HEX, _T0)
        self.assertTrue(v2.allowed)

    def test_low_confidence_cannot_authorize(self):
        reg = DetectionRegistry()
        claim, v = reg.detection_receipt(
            detection_id="d2", claim_digest=_HEX, confidence=0.4,
            fit_evidence_digest=_HEX, detector_id="mapl-emit-1",
            detected_unix=_T0)
        self.assertFalse(v.allowed)
        self.assertFalse(claim.usable_as_evidence)
        self.assertIn(DENY_INSUFFICIENT_CONFIDENCE, v.reason)
        v2 = reg.authorize_action_on_detection("d2", _HEX, _T0)
        self.assertFalse(v2.allowed)
        self.assertIn(DENY_INSUFFICIENT_CONFIDENCE, v2.reason)

    def test_threshold_boundary(self):
        reg = DetectionRegistry()
        _c, v = reg.detection_receipt(
            detection_id="db", claim_digest=_HEX,
            confidence=DETECTION_CONFIDENCE_MIN,
            fit_evidence_digest=_HEX, detector_id="x", detected_unix=_T0)
        self.assertTrue(v.allowed)

    def test_unknown_detection_denies(self):
        reg = DetectionRegistry()
        v = reg.authorize_action_on_detection("nope", _HEX, _T0)
        self.assertFalse(v.allowed)


class MaturityTests(unittest.TestCase):
    def test_experimental_non_authoritative(self):
        reg = MaturityRegistry()
        reg.register(system_id="wx3", model_digest=_HEX,
                     maturity="experimental",
                     deployment_receipt_digest=_HEX, registered_by="ops",
                     registered_at=_T0)
        v = reg.classify_output("wx3")
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, "NON_AUTHORITATIVE")

    def test_production_authoritative(self):
        reg = MaturityRegistry()
        reg.register(system_id="prod1", model_digest=_HEX,
                     maturity="production",
                     deployment_receipt_digest=_HEX, registered_by="ops",
                     registered_at=_T0)
        v = reg.classify_output("prod1")
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "AUTHORITATIVE")

    def test_relabel_refused(self):
        reg = MaturityRegistry()
        reg.register(system_id="s1", model_digest=_HEX,
                     maturity="experimental",
                     deployment_receipt_digest=_HEX, registered_by="ops",
                     registered_at=_T0)
        with self.assertRaises(EnvCostError):
            reg.register(system_id="s1", model_digest=_HEX,
                         maturity="production",
                         deployment_receipt_digest=_HEX, registered_by="ops",
                         registered_at=_T0 + 1)


class PhysicsGateTests(unittest.TestCase):
    def test_matching_constraints_allows(self):
        gate, list_digest = _physics_gate()
        v = gate.authorize_extrapolation("coast-sim", list_digest, _T0)
        self.assertTrue(v.allowed)

    def test_gap_non_authoritative(self):
        gate, _ = _physics_gate()
        v = gate.authorize_extrapolation("coast-sim", _HEX, _T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_PHYSICS_GAP, v.reason)
        self.assertEqual(v.classification, "NON_AUTHORITATIVE")

    def test_no_binding_denies(self):
        gate = PhysicsGate()
        v = gate.authorize_extrapolation("unbound", _HEX, _T0)
        self.assertFalse(v.allowed)


class ActionLinkTests(unittest.TestCase):
    def test_confirm_links_detection(self):
        reg = DetectionRegistry()
        reg.detection_receipt(
            detection_id="d1", claim_digest=_HEX, confidence=0.9,
            fit_evidence_digest=_HEX, detector_id="x", detected_unix=_T0)
        linker = ActionLinker(reg)
        self.assertEqual(linker.link_status("d1"), "open-loop")
        confirmation, v = linker.confirm_action("d1", _HEX, "ops-team",
                                                _T0 + 60)
        self.assertTrue(v.allowed)
        self.assertEqual(confirmation.detection_id, "d1")
        self.assertEqual(linker.link_status("d1"), "confirmed")

    def test_confirm_low_confidence_denies(self):
        reg = DetectionRegistry()
        reg.detection_receipt(
            detection_id="d2", claim_digest=_HEX, confidence=0.3,
            fit_evidence_digest=_HEX, detector_id="x", detected_unix=_T0)
        linker = ActionLinker(reg)
        _c, v = linker.confirm_action("d2", _HEX, "ops-team", _T0 + 60)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_INSUFFICIENT_CONFIDENCE, v.reason)
        self.assertEqual(linker.link_status("d2"), "open-loop")


class EfficiencyClaimTests(unittest.TestCase):
    def test_claim_ok(self):
        reg = EfficiencyClaimRegistry()
        record, v = reg.register_efficiency_claim(
            claim_id="e1", claim_digest=_HEX,
            named_platform="H100-SXM-80GB-node7",
            measured_metrics_digest=_HEX, claimed_by="lab",
            created_unix=_T0)
        self.assertTrue(v.allowed)
        self.assertEqual(record.named_platform, "H100-SXM-80GB-node7")

    def test_no_platform_unverifiable(self):
        reg = EfficiencyClaimRegistry()
        record, v = reg.register_efficiency_claim(
            claim_id="e2", claim_digest=_HEX, named_platform="",
            measured_metrics_digest=_HEX, claimed_by="lab",
            created_unix=_T0)
        self.assertIsNone(record)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNVERIFIABLE_EFFICIENCY, v.reason)
        self.assertEqual(v.classification, "unverifiable-claim")

    def test_unpinned_metrics_unverifiable(self):
        reg = EfficiencyClaimRegistry()
        _record, v = reg.register_efficiency_claim(
            claim_id="e3", claim_digest=_HEX, named_platform="H100",
            measured_metrics_digest="not-a-digest", claimed_by="lab",
            created_unix=_T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNVERIFIABLE_EFFICIENCY, v.reason)


if __name__ == "__main__":
    unittest.main()
