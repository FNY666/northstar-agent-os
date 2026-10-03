"""Tests for embodied.py (one-hundred-twenty-sixth batch).

Deterministic: pinned keys, pinned times. No network, no clock reads.
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ed25519 import public_key, sign

from embodied import (
    DENY_INCIDENT_UNREPORTED,
    DENY_LABOR_IMPACT_UNDISCLOSED,
    DENY_LOW_CONFIDENCE_RELEASE,
    DENY_NO_FALL_ZONE,
    DENY_NO_STANDARD_DECLARATION,
    DENY_PRESCRIPTIVE_ENVELOPE_WIDENED,
    DENY_PRESCRIPTIVE_OUT_OF_SCOPE,
    DENY_UNAUDITED_DISPATCH,
    DENY_UNSUBSTANTIATED_CAPABILITY,
    DENY_UNVERIFIABLE_SAFETY,
    AuthorityRegistry,
    CapabilityRegistry,
    DispatchLedger,
    EmbodiedError,
    FallZoneRegistry,
    LaborRegistry,
    PrescriptiveRegistry,
    StandardRegistry,
    embodied_audit_event,
    incident_binding,
    inspection_confidence_gate,
)

AUTH_SEC = b"authority-seed-00000000000000001"  # 32 bytes
AUTH2_SEC = b"authority-seed-00000000000000002"
AUTH_PUB = public_key(AUTH_SEC)
AUTH2_PUB = public_key(AUTH2_SEC)
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32


def _authorities() -> AuthorityRegistry:
    reg = AuthorityRegistry()
    reg.register("op-alice", AUTH_PUB)
    reg.register("op-bob", AUTH2_PUB)
    return reg


class StandardDeclarationTest(unittest.TestCase):
    def test_no_declaration_fails_closed(self) -> None:
        reg = StandardRegistry(_authorities())
        v = reg.safety_vacuum_gate(deployment_id="dep-1", now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_NO_STANDARD_DECLARATION)

    def test_pre_ratification_declaration_allows(self) -> None:
        reg = StandardRegistry(_authorities())
        from embodied import compute_standard_digest
        digest = compute_standard_digest(
            deployment_id="dep-1", standard_id="ISO-25785-1",
            standard_status="pre_ratification", cert_digest="00" * 32,
            draft_standard_digest=HEX64, citizen_ack_digest=HEX64_B,
            declared_by="op-alice", declared_at=T0,
        )
        reg.declare(
            deployment_id="dep-1", standard_id="ISO-25785-1",
            standard_status="pre_ratification", cert_digest="00" * 32,
            draft_standard_digest=HEX64, citizen_ack_digest=HEX64_B,
            declared_by="op-alice", declared_at=T0,
            signature=sign(AUTH_SEC, digest.encode()),
        )
        v = reg.safety_vacuum_gate(deployment_id="dep-1", now=T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.declaration.standard_status, "pre_ratification")

    def test_certified_declaration_allows(self) -> None:
        reg = StandardRegistry(_authorities())
        from embodied import compute_standard_digest
        digest = compute_standard_digest(
            deployment_id="dep-2", standard_id="ISO-10218",
            standard_status="certified", cert_digest=HEX64,
            draft_standard_digest=HEX64, citizen_ack_digest=HEX64,
            declared_by="op-bob", declared_at=T0,
        )
        reg.declare(
            deployment_id="dep-2", standard_id="ISO-10218",
            standard_status="certified", cert_digest=HEX64,
            draft_standard_digest=HEX64, citizen_ack_digest=HEX64,
            declared_by="op-bob", declared_at=T0,
            signature=sign(AUTH2_SEC, digest.encode()),
        )
        v = reg.safety_vacuum_gate(deployment_id="dep-2", now=T0)
        self.assertTrue(v.allowed)

    def test_bad_signature_rejected_at_declare(self) -> None:
        reg = StandardRegistry(_authorities())
        with self.assertRaises(EmbodiedError):
            reg.declare(
                deployment_id="dep-3", standard_id="ISO-25785-1",
                standard_status="pre_ratification", cert_digest="00" * 32,
                draft_standard_digest=HEX64, citizen_ack_digest=HEX64_B,
                declared_by="op-alice", declared_at=T0,
                signature=b"\x01" * 64,
            )

    def test_declaration_from_future_fails_closed(self) -> None:
        reg = StandardRegistry(_authorities())
        from embodied import compute_standard_digest
        digest = compute_standard_digest(
            deployment_id="dep-4", standard_id="ISO-25785-1",
            standard_status="pre_ratification", cert_digest="00" * 32,
            draft_standard_digest=HEX64, citizen_ack_digest=HEX64_B,
            declared_by="op-alice", declared_at=T0 + 100,
        )
        reg.declare(
            deployment_id="dep-4", standard_id="ISO-25785-1",
            standard_status="pre_ratification", cert_digest="00" * 32,
            draft_standard_digest=HEX64, citizen_ack_digest=HEX64_B,
            declared_by="op-alice", declared_at=T0 + 100,
            signature=sign(AUTH_SEC, digest.encode()),
        )
        v = reg.safety_vacuum_gate(deployment_id="dep-4", now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_UNVERIFIABLE_SAFETY)


class FallZoneTest(unittest.TestCase):
    def _issue(self, reg, rid="fz-1", dep="dep-1", prox="close_contact"):
        from embodied import compute_fall_zone_digest
        digest = compute_fall_zone_digest(
            receipt_id=rid, deployment_id=dep, proximity_class=prox,
            fall_zone_m=3.5, computation_digest=HEX64,
            computed_by="op-alice", computed_at=T0,
        )
        return reg.issue(
            receipt_id=rid, deployment_id=dep, proximity_class=prox,
            fall_zone_m=3.5, computation_digest=HEX64,
            computed_by="op-alice", computed_at=T0,
            signature=sign(AUTH_SEC, digest.encode()),
        )

    def test_remote_needs_no_receipt(self) -> None:
        reg = FallZoneRegistry(_authorities())
        v = reg.check_actuation(
            deployment_id="dep-1", proximity_class="remote", now=T0)
        self.assertTrue(v.allowed)

    def test_close_contact_without_receipt_denies(self) -> None:
        reg = FallZoneRegistry(_authorities())
        v = reg.check_actuation(
            deployment_id="dep-1", proximity_class="close_contact", now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_NO_FALL_ZONE)

    def test_fresh_receipt_allows(self) -> None:
        reg = FallZoneRegistry(_authorities())
        self._issue(reg)
        v = reg.check_actuation(
            deployment_id="dep-1", proximity_class="close_contact",
            now=T0 + 3600)
        self.assertTrue(v.allowed)

    def test_stale_receipt_denies(self) -> None:
        reg = FallZoneRegistry(_authorities())
        self._issue(reg)
        v = reg.check_actuation(
            deployment_id="dep-1", proximity_class="close_contact",
            now=T0 + 25 * 3600)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_NO_FALL_ZONE)

    def test_revoked_receipt_denies(self) -> None:
        reg = FallZoneRegistry(_authorities())
        self._issue(reg)
        reg.revoke("fz-1")
        v = reg.check_actuation(
            deployment_id="dep-1", proximity_class="close_contact", now=T0)
        self.assertFalse(v.allowed)


class CapabilityHonestyTest(unittest.TestCase):
    def _label(self, reg, lid="cl-1", measured=True, by="op-alice", sec=AUTH_SEC):
        from embodied import compute_label_digest
        dg = compute_label_digest(
            label_id=lid, deployment_id="dep-1",
            claim="50% of human speed", measured=measured,
            benchmark_id="bench-v3", benchmark_digest=HEX64 if measured else "00" * 32,
            labeled_by=by, labeled_at=T0,
        )
        return reg.label(
            label_id=lid, deployment_id="dep-1", claim="50% of human speed",
            measured=measured, benchmark_id="bench-v3",
            benchmark_digest=HEX64 if measured else "00" * 32,
            labeled_by=by, labeled_at=T0, signature=sign(sec, dg.encode()),
        )

    def test_measured_claim_honest(self) -> None:
        reg = CapabilityRegistry(_authorities())
        self._label(reg)
        v = reg.capability_honesty_label(label_id="cl-1", now=T0)
        self.assertTrue(v.allowed)

    def test_unmeasured_claim_denies(self) -> None:
        reg = CapabilityRegistry(_authorities())
        self._label(reg, measured=False)
        v = reg.capability_honesty_label(label_id="cl-1", now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_UNSUBSTANTIATED_CAPABILITY)

    def test_missing_label_denies(self) -> None:
        reg = CapabilityRegistry(_authorities())
        v = reg.capability_honesty_label(label_id="nope", now=T0)
        self.assertFalse(v.allowed)


class LaborImpactTest(unittest.TestCase):
    def _record(self, reg, dep="dep-1", estimate=40, disclosed=True):
        from embodied import compute_labor_digest
        digest = compute_labor_digest(
            receipt_id="li-1", deployment_id=dep,
            workers_displaced_estimate=estimate,
            retraining_plan_digest=HEX64, labor_agreement_digest="00" * 32,
            disclosed=disclosed, recorded_by="op-alice", recorded_at=T0,
        )
        return reg.record(
            receipt_id="li-1", deployment_id=dep,
            workers_displaced_estimate=estimate,
            retraining_plan_digest=HEX64, labor_agreement_digest="00" * 32,
            disclosed=disclosed, recorded_by="op-alice", recorded_at=T0,
            signature=sign(AUTH_SEC, digest.encode()),
        )

    def test_below_threshold_no_disclosure_needed(self) -> None:
        reg = LaborRegistry(_authorities())
        v = reg.labor_impact_receipt(
            deployment_id="dep-1", workers_displaced_estimate=5, now=T0)
        self.assertTrue(v.allowed)
        self.assertFalse(v.mandatory_disclosure)

    def test_at_threshold_undisclosed_denies(self) -> None:
        reg = LaborRegistry(_authorities())
        v = reg.labor_impact_receipt(
            deployment_id="dep-1", workers_displaced_estimate=10, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_LABOR_IMPACT_UNDISCLOSED)
        self.assertTrue(v.mandatory_disclosure)

    def test_disclosed_allows(self) -> None:
        reg = LaborRegistry(_authorities())
        self._record(reg)
        v = reg.labor_impact_receipt(
            deployment_id="dep-1", workers_displaced_estimate=40, now=T0)
        self.assertTrue(v.allowed)


class PrescriptiveAgentTest(unittest.TestCase):
    def _arm(self, reg, agent="pa-1", actions=("create_work_order",)):
        from embodied import compute_prescriptive_digest
        digest = compute_prescriptive_digest(
            envelope_id="pe-1", agent_id=agent,
            allowed_actions=tuple(sorted(actions)), scope_digest=HEX64,
            armed_by="op-alice", armed_at=T0, expires_at=T0 + 3600,
        )
        return reg.arm(
            envelope_id="pe-1", agent_id=agent, allowed_actions=actions,
            scope_digest=HEX64, armed_by="op-alice",
            armed_at=T0, expires_at=T0 + 3600,
            signature=sign(AUTH_SEC, digest.encode()),
        )

    def test_in_scope_action_allows(self) -> None:
        reg = PrescriptiveRegistry(_authorities())
        self._arm(reg)
        v = reg.prescriptive_agent_gate(
            agent_id="pa-1", action="create_work_order",
            scope_digest=HEX64, now=T0 + 10)
        self.assertTrue(v.allowed)

    def test_out_of_scope_action_denies(self) -> None:
        reg = PrescriptiveRegistry(_authorities())
        self._arm(reg)
        v = reg.prescriptive_agent_gate(
            agent_id="pa-1", action="order_parts",
            scope_digest=HEX64, now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_PRESCRIPTIVE_OUT_OF_SCOPE)

    def test_agent_cannot_widen_own_envelope(self) -> None:
        reg = PrescriptiveRegistry(_authorities())
        self._arm(reg)
        with self.assertRaises(EmbodiedError) as ctx:
            reg.widen(
                agent_id="pa-1",
                allowed_actions=("create_work_order", "order_parts"),
                approved_by="op-alice", signature=b"\x00" * 64, now=T0 + 10,
            )
        self.assertIn(DENY_PRESCRIPTIVE_ENVELOPE_WIDENED, str(ctx.exception))


class InspectionGateTest(unittest.TestCase):
    def test_measured_pass_above_threshold_releases(self) -> None:
        v = inspection_confidence_gate(
            inspection_id="i-1", verdict="pass", confidence=0.99,
            measured=True, confidence_threshold=0.97,
            now=T0, decided_at=T0)
        self.assertTrue(v.auto_release)

    def test_below_threshold_no_release(self) -> None:
        v = inspection_confidence_gate(
            inspection_id="i-1", verdict="pass", confidence=0.90,
            measured=True, confidence_threshold=0.97,
            now=T0, decided_at=T0)
        self.assertFalse(v.auto_release)
        self.assertEqual(v.deny_code, DENY_LOW_CONFIDENCE_RELEASE)

    def test_unmeasured_confidence_no_release(self) -> None:
        v = inspection_confidence_gate(
            inspection_id="i-1", verdict="pass", confidence=0.99,
            measured=False, confidence_threshold=0.97,
            now=T0, decided_at=T0)
        self.assertFalse(v.auto_release)


class DispatchLedgerTest(unittest.TestCase):
    def _record(self, ledger, did="d-1"):
        from embodied import compute_dispatch_digest
        digest = compute_dispatch_digest(
            dispatch_id=did, project_id="proj-1", robot_id="r-1",
            task_digest=HEX64, window_start=T0, window_end=T0 + 3600,
            dispatched_by="op-alice", dispatched_at=T0, prev_hash="genesis",
        )
        return ledger.record(
            dispatch_id=did, project_id="proj-1", robot_id="r-1",
            task_digest=HEX64, window_start=T0, window_end=T0 + 3600,
            dispatched_by="op-alice", dispatched_at=T0,
            signature=sign(AUTH_SEC, digest.encode()),
        )

    def test_recorded_dispatch_audited(self) -> None:
        ledger = DispatchLedger(_authorities())
        self._record(ledger)
        v = ledger.dispatch_audit(dispatch_id="d-1", now=T0 + 60)
        self.assertTrue(v.audited)

    def test_unknown_dispatch_denies(self) -> None:
        ledger = DispatchLedger(_authorities())
        v = ledger.dispatch_audit(dispatch_id="ghost", now=T0)
        self.assertFalse(v.audited)
        self.assertEqual(v.deny_code, DENY_UNAUDITED_DISPATCH)


class IncidentBindingTest(unittest.TestCase):
    class _FakeRegistry:
        def __init__(self, miss: bool) -> None:
            self._miss = miss

        def file_incident(self, **kwargs):  # noqa: ANN003, ANN202
            class V:
                clock_missed = self._miss
            return V()

    def test_filed_on_time_reports(self) -> None:
        link = incident_binding(
            incident_registry=self._FakeRegistry(False),
            incident_id="inc-1", system_id="sys-1", severity="serious",
            death_linked=False, widespread=False, systemic_tier=None,
            detected_at=T0, reported_at=T0 + 10, summary_digest=HEX64, now=T0 + 20,
        )
        self.assertTrue(link.reported)
        self.assertFalse(link.escalated)
        self.assertIsNone(link.deny_code)

    def test_filing_failure_escalates(self) -> None:
        class _Boom:
            def file_incident(self, **kwargs):  # noqa: ANN003, ANN202
                raise RuntimeError("downstream down")
        link = incident_binding(
            incident_registry=_Boom(),
            incident_id="inc-2", system_id="sys-1", severity="serious",
            death_linked=False, widespread=False, systemic_tier=None,
            detected_at=T0, reported_at=T0 + 10, summary_digest=HEX64, now=T0 + 20,
        )
        self.assertFalse(link.reported)
        self.assertTrue(link.escalated)
        self.assertEqual(link.deny_code, DENY_INCIDENT_UNREPORTED)


class AuditEventTest(unittest.TestCase):
    def test_audit_event_has_digest(self) -> None:
        ev = embodied_audit_event(
            "embodied.actuation_denied", deployment_id="dep-1",
            deny_code=DENY_NO_FALL_ZONE, now=T0)
        self.assertEqual(len(ev["event_digest"]), 64)
        self.assertEqual(ev["deny_code"], DENY_NO_FALL_ZONE)


if __name__ == "__main__":
    unittest.main()
