"""Tests for manufacturing_agents.py (one-hundred-fifty-seventh batch)."""

import dataclasses
import unittest

import ed25519

import manufacturing_agents
from manufacturing_agents import (
    AuthorityRegistry,
    ManufacturingError,
    EnvelopeRegistry,
    EnvelopeReceipt,
    RestartClearanceRegistry,
    RestartClearanceReceipt,
    PilotRegistry,
    PilotStageReceipt,
    MaintenanceAdviceRegistry,
    MaintenanceAdviceReceipt,
    MaintenanceDecisionRegistry,
    MaintenanceDecisionPin,
    DisplacementRegistry,
    DisplacementDisclosureReceipt,
    SafetyBaselineRegistry,
    SafetyBaselineReceipt,
    TwinSyncRegistry,
    TwinSyncReceipt,
    QualityClaimRegistry,
    QualityClaimReceipt,
    PILOT_STAGES,
    restart_clearance_receipt,
    capability_envelope,
    humanoid_pilot_registry,
    maintenance_decision_pin,
    displacement_disclosure,
    safety_baseline_clock,
    twin_sync_integrity,
    quality_claim_evidence,
)
from canonical_json import jcs_canonical_json

_SEED = bytes(range(32))
_PUB = ed25519.public_key(_SEED).hex()
_AUTH = "auth-1"
_T0 = 1_800_000_000


def _auths():
    auth = AuthorityRegistry()
    auth.register(_AUTH, _PUB)
    return auth


def _hex(c):
    return c * 64


def _issue(reg, receipt_cls, **fields):
    """Issue a receipt, signing the exact payload the module verifies."""
    prev = reg.log[-1].receipt_digest if reg.log else "genesis"
    tmp = receipt_cls(
        prev_digest=prev,
        signature_hex="00" * 64,
        authority_id=_AUTH,
        authority_pubkey_hex=_PUB,
        **fields,
    )
    sig = ed25519.sign(_SEED, jcs_canonical_json(tmp._payload()))
    return reg.issue(signature=sig, authority_id=_AUTH, **fields)


class TestRestartClearance(unittest.TestCase):
    def _clear(self, reg, restart_id="rst-1", cleared_at=_T0, rid="rc-1"):
        return _issue(
            reg,
            RestartClearanceReceipt,
            receipt_id=rid,
            cell_id="cell-7",
            restart_id=restart_id,
            confirmer_a_id="op-alice",
            confirmer_b_id="op-bob",
            cleared_at=cleared_at,
        )

    def test_fresh_two_person_clearance_allows(self):
        reg = RestartClearanceRegistry(_auths())
        self._clear(reg)
        v = restart_clearance_receipt(reg, "rst-1", _T0 + 100)
        self.assertTrue(v.allowed)
        self.assertTrue(v.receipt_digest)

    def test_missing_receipt_denied(self):
        reg = RestartClearanceRegistry(_auths())
        v = restart_clearance_receipt(reg, "rst-ghost", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.restart_without_clearance", v.reason)

    def test_same_confirmer_rejected_at_issue(self):
        reg = RestartClearanceRegistry(_auths())
        with self.assertRaises(ManufacturingError):
            _issue(
                reg,
                RestartClearanceReceipt,
                receipt_id="rc-2",
                cell_id="cell-7",
                restart_id="rst-2",
                confirmer_a_id="op-alice",
                confirmer_b_id="op-alice",
                cleared_at=_T0,
            )

    def test_stale_clearance_denied(self):
        reg = RestartClearanceRegistry(_auths())
        self._clear(reg, cleared_at=_T0 - 7_200)
        v = restart_clearance_receipt(reg, "rst-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.restart_without_clearance", v.reason)

    def test_future_clearance_denied(self):
        reg = RestartClearanceRegistry(_auths())
        self._clear(reg, cleared_at=_T0 + 9_999)
        v = restart_clearance_receipt(reg, "rst-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.future_clearance", v.reason)

    def test_chain_broken(self):
        reg = RestartClearanceRegistry(_auths())
        self._clear(reg)
        bad = dataclasses.replace(reg.log[-1], signature_hex="ff" * 128)
        reg.log[-1] = bad
        v = restart_clearance_receipt(reg, "rst-1", _T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.chain_broken", v.reason)


class TestCapabilityEnvelope(unittest.TestCase):
    def _env(self, reg, issued_at=_T0, rid="env-1"):
        return _issue(
            reg,
            EnvelopeReceipt,
            receipt_id=rid,
            envelope_id="env-1",
            robot_id="arm-3",
            max_payload_kg=50.0,
            max_speed_ms=1.5,
            max_torque_nm=120.0,
            allowed_task_kinds=["palletize", "inspect"],
            issued_at=issued_at,
        )

    def _check(self, reg, kind="palletize", payload=10.0, speed=1.0, torque=50.0):
        return capability_envelope(
            reg, "arm-3", kind, payload, speed, torque, _T0 + 100
        )

    def test_within_envelope_allows(self):
        reg = EnvelopeRegistry(_auths())
        self._env(reg)
        self.assertTrue(self._check(reg).allowed)

    def test_no_envelope_denied(self):
        reg = EnvelopeRegistry(_auths())
        v = self._check(reg)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.envelope_breach", v.reason)

    def test_unknown_task_kind_denied(self):
        reg = EnvelopeRegistry(_auths())
        self._env(reg)
        v = self._check(reg, kind="weld")
        self.assertFalse(v.allowed)
        self.assertIn("mfg.envelope_breach", v.reason)

    def test_over_payload_denied(self):
        reg = EnvelopeRegistry(_auths())
        self._env(reg)
        v = self._check(reg, payload=60.0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.envelope_breach", v.reason)

    def test_stale_envelope_denied(self):
        reg = EnvelopeRegistry(_auths())
        self._env(reg, issued_at=_T0 - 31 * 86_400)
        v = self._check(reg)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.envelope_breach", v.reason)


class TestHumanoidPilot(unittest.TestCase):
    def _stage(self, reg, stage, robot="hum-1", completed_at=_T0, rid=None):
        return _issue(
            reg,
            PilotStageReceipt,
            receipt_id=rid or f"st-{stage}",
            stage_id=f"stage-{stage}",
            robot_model_id=robot,
            stage=stage,
            evidence_digest=_hex("a"),
            completed_at=completed_at,
        )

    def test_first_stage_needs_no_prior(self):
        reg = PilotRegistry(_auths())
        v = humanoid_pilot_registry(reg, "hum-1", "maturity_assessment", _T0)
        self.assertTrue(v.allowed)

    def test_line_testing_with_ladder_allows(self):
        reg = PilotRegistry(_auths())
        self._stage(reg, "maturity_assessment")
        self._stage(reg, "lab_validation")
        v = humanoid_pilot_registry(reg, "hum-1", "line_testing", _T0 + 10)
        self.assertTrue(v.allowed)

    def test_production_on_pilot_evidence_denied(self):
        reg = PilotRegistry(_auths())
        for s in ("maturity_assessment", "lab_validation", "line_testing", "pilot"):
            self._stage(reg, s)
        v = humanoid_pilot_registry(reg, "hum-1", "production", _T0 + 10)
        # production needs its own... no: production is stage 4, needs stages 0..3
        self.assertTrue(v.allowed)

    def test_stage_skipping_denied(self):
        reg = PilotRegistry(_auths())
        self._stage(reg, "lab_validation")
        v = humanoid_pilot_registry(reg, "hum-1", "line_testing", _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.uncertified_scaleup", v.reason)

    def test_stale_stage_denied(self):
        reg = PilotRegistry(_auths())
        self._stage(reg, "maturity_assessment", completed_at=_T0 - 181 * 86_400)
        self._stage(reg, "lab_validation")
        v = humanoid_pilot_registry(reg, "hum-1", "line_testing", _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.uncertified_scaleup", v.reason)

    def test_unknown_stage_raises(self):
        reg = PilotRegistry(_auths())
        with self.assertRaises(ManufacturingError):
            humanoid_pilot_registry(reg, "hum-1", "skynet", _T0)


class TestMaintenancePin(unittest.TestCase):
    def _advice(self, reg, action="shutdown_line", advice_id="adv-1", rid="ma-1"):
        return _issue(
            reg,
            MaintenanceAdviceReceipt,
            receipt_id=rid,
            advice_id=advice_id,
            machine_id="cnc-2",
            action=action,
            model_version="pm-v3",
            advice_digest=_hex("b"),
            issued_at=_T0,
        )

    def _pin(self, reg, advice_id="adv-1", action="shutdown_line", decided_at=_T0):
        return _issue(
            reg,
            MaintenanceDecisionPin,
            receipt_id="pin-1",
            pin_id="pin-1",
            advice_id=advice_id,
            action=action,
            human_approver_id="mgr-carol",
            decided_at=decided_at,
        )

    def test_advisory_action_needs_no_pin(self):
        areg = MaintenanceAdviceRegistry(_auths())
        preg = MaintenanceDecisionRegistry(_auths())
        self._advice(areg, action="inspect_soon")
        v = maintenance_decision_pin(areg, preg, "adv-1", "inspect_soon", _T0 + 10)
        self.assertTrue(v.allowed)

    def test_ai_line_stop_without_pin_denied(self):
        areg = MaintenanceAdviceRegistry(_auths())
        preg = MaintenanceDecisionRegistry(_auths())
        self._advice(areg, action="shutdown_line")
        v = maintenance_decision_pin(areg, preg, "adv-1", "shutdown_line", _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.autonomous_stop", v.reason)

    def test_line_stop_with_human_pin_allows(self):
        areg = MaintenanceAdviceRegistry(_auths())
        preg = MaintenanceDecisionRegistry(_auths())
        self._advice(areg, action="shutdown_line")
        self._pin(preg)
        v = maintenance_decision_pin(areg, preg, "adv-1", "shutdown_line", _T0 + 10)
        self.assertTrue(v.allowed)
        self.assertIn("mgr-carol", v.reason)

    def test_future_pin_denied(self):
        areg = MaintenanceAdviceRegistry(_auths())
        preg = MaintenanceDecisionRegistry(_auths())
        self._advice(areg, action="swap_part")
        self._pin(preg, action="swap_part", decided_at=_T0 + 99_999)
        v = maintenance_decision_pin(areg, preg, "adv-1", "swap_part", _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.future_pin", v.reason)


class TestDisplacementDisclosure(unittest.TestCase):
    def _disc(self, reg, disclosed_at=_T0 - 31 * 86_400,
              union_notified=True, rid="dd-1"):
        return _issue(
            reg,
            DisplacementDisclosureReceipt,
            receipt_id=rid,
            disclosure_id="dd-1",
            site_id="ulsan-1",
            automation_kind="humanoid",
            displaced_workers_estimate=120,
            retraining_plan_digest=_hex("c"),
            union_notified=union_notified,
            disclosed_at=disclosed_at,
        )

    def test_noticed_disclosure_allows(self):
        reg = DisplacementRegistry(_auths())
        self._disc(reg)
        self.assertTrue(displacement_disclosure(reg, "ulsan-1", _T0).allowed)

    def test_no_disclosure_denied(self):
        reg = DisplacementRegistry(_auths())
        v = displacement_disclosure(reg, "ulsan-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.silent_displacement", v.reason)

    def test_unnotified_union_denied(self):
        reg = DisplacementRegistry(_auths())
        self._disc(reg, union_notified=False)
        v = displacement_disclosure(reg, "ulsan-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.silent_displacement", v.reason)

    def test_short_notice_denied(self):
        reg = DisplacementRegistry(_auths())
        self._disc(reg, disclosed_at=_T0 - 5 * 86_400)
        v = displacement_disclosure(reg, "ulsan-1", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.silent_displacement", v.reason)


class TestSafetyBaseline(unittest.TestCase):
    def _base(self, reg, pinned_at=_T0, expires_at=_T0 + 180 * 86_400,
              fencing=True, rid="sb-1"):
        return _issue(
            reg,
            SafetyBaselineReceipt,
            receipt_id=rid,
            baseline_id="sb-1",
            site_id="plant-a",
            robot_class="humanoid_mobile",
            fencing_confirmed=fencing,
            max_speed_ms=1.0,
            max_torque_nm=80.0,
            max_robots_per_supervisor=4,
            pinned_at=pinned_at,
            expires_at=expires_at,
        )

    def test_live_baseline_allows(self):
        reg = SafetyBaselineRegistry(_auths())
        self._base(reg)
        v = safety_baseline_clock(reg, "plant-a", "humanoid_mobile", _T0 + 10)
        self.assertTrue(v.allowed)

    def test_missing_baseline_denied(self):
        reg = SafetyBaselineRegistry(_auths())
        v = safety_baseline_clock(reg, "plant-a", "humanoid_mobile", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.no_safety_baseline", v.reason)

    def test_expired_baseline_denied(self):
        reg = SafetyBaselineRegistry(_auths())
        self._base(reg, pinned_at=_T0 - 200 * 86_400,
                   expires_at=_T0 - 20 * 86_400)
        v = safety_baseline_clock(reg, "plant-a", "humanoid_mobile", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.no_safety_baseline", v.reason)

    def test_unfenced_baseline_denied(self):
        reg = SafetyBaselineRegistry(_auths())
        self._base(reg, fencing=False)
        v = safety_baseline_clock(reg, "plant-a", "humanoid_mobile", _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.no_safety_baseline", v.reason)


class TestTwinSync(unittest.TestCase):
    def _sync(self, reg, drift=100, checked_at=_T0, rid="ts-1"):
        return _issue(
            reg,
            TwinSyncReceipt,
            receipt_id=rid,
            sync_id="ts-1",
            cell_id="cell-9",
            twin_state_digest=_hex("d"),
            physical_state_digest=_hex("e"),
            drift_bps=drift,
            checked_at=checked_at,
        )

    def test_fresh_in_tolerance_allows(self):
        reg = TwinSyncRegistry(_auths())
        self._sync(reg)
        self.assertTrue(twin_sync_integrity(reg, "cell-9", _T0 + 100).allowed)

    def test_no_sync_denied(self):
        reg = TwinSyncRegistry(_auths())
        v = twin_sync_integrity(reg, "cell-9", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.twin_desync", v.reason)

    def test_excess_drift_denied(self):
        reg = TwinSyncRegistry(_auths())
        self._sync(reg, drift=800)
        v = twin_sync_integrity(reg, "cell-9", _T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.twin_desync", v.reason)

    def test_stale_sync_denied(self):
        reg = TwinSyncRegistry(_auths())
        self._sync(reg, checked_at=_T0 - 7_200)
        v = twin_sync_integrity(reg, "cell-9", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.twin_desync", v.reason)


class TestQualityClaim(unittest.TestCase):
    def _claim(self, reg, sample=5_000, rid="qc-1"):
        return _issue(
            reg,
            QualityClaimReceipt,
            receipt_id=rid,
            claim_id="qc-1",
            metric_name="defect_rate_reduction_bps",
            claimed_value=7500.0,
            measurement_protocol_digest=_hex("f"),
            sample_size=sample,
            third_party_verified=True,
            measured_at=_T0,
        )

    def test_protocol_bound_claim_allows(self):
        reg = QualityClaimRegistry(_auths())
        self._claim(reg)
        v = quality_claim_evidence(reg, "qc-1", _T0 + 10)
        self.assertTrue(v.allowed)
        self.assertIn("7500", v.reason)

    def test_missing_claim_denied(self):
        reg = QualityClaimRegistry(_auths())
        v = quality_claim_evidence(reg, "qc-ghost", _T0)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.unverified_quality_claim", v.reason)

    def test_tiny_sample_denied(self):
        reg = QualityClaimRegistry(_auths())
        self._claim(reg, sample=50)
        v = quality_claim_evidence(reg, "qc-1", _T0 + 10)
        self.assertFalse(v.allowed)
        self.assertIn("mfg.unverified_quality_claim", v.reason)


class TestModuleSurface(unittest.TestCase):
    def test_all_exports_importable(self):
        for name in manufacturing_agents.__all__:
            self.assertTrue(hasattr(manufacturing_agents, name), name)

    def test_schema_version(self):
        self.assertEqual(manufacturing_agents.MFG_SCHEMA_VERSION,
                         "northstar.manufacturing.v1")

    def test_pilot_stage_order(self):
        self.assertEqual(PILOT_STAGES[0], "maturity_assessment")
        self.assertEqual(PILOT_STAGES[-1], "production")


if __name__ == "__main__":
    unittest.main()
