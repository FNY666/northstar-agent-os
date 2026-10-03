"""Tests for labor_algo.py (one-hundred-twenty-seventh batch).

Deterministic: pinned keys, pinned times. No network, no clock reads.
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ed25519 import public_key, sign

from labor_algo import (
    DENY_ALGORITHMIC_FIRING,
    DENY_AV_SAFETY_CASE_REVOKED,
    DENY_BIOMETRIC_SURVEILLANCE_UNDECLARED,
    DENY_DISPROPORTIONATE_SURVEILLANCE,
    DENY_FATIGUE_CIRCUIT_BREAK,
    DENY_HIDDEN_QUOTA,
    DENY_LABOR_IMPACT_UNDISCLOSED,
    DENY_NO_FATIGUE_POLICY,
    DENY_NO_SAFETY_CASE,
    DENY_NO_SURVEILLANCE_RECEIPT,
    DENY_QUOTA_ACK_MISSING,
    DENY_QUOTA_DIGEST_MISMATCH,
    DENY_REJECTION_PENALTY,
    DENY_SURVEILLANCE_PURPOSE_MISMATCH,
    DENY_SURVEILLANCE_RETENTION_EXCEEDED,
    DENY_UNKNOWN_AUTHORITY,
    AuthorityRegistry,
    AVSafetyRegistry,
    DispatchRegistry,
    FatigueBreaker,
    LaborAlgoError,
    LaborImpactRegistry,
    QuotaRegistry,
    SurveillanceRegistry,
    TerminationRegistry,
    compute_av_digest,
    compute_quota_digest,
    compute_termination_digest,
    labor_audit_event,
)

AUTH_SEC = b"authority-seed-00000000000000001"  # 32 bytes
AUTH2_SEC = b"authority-seed-00000000000000002"
WORKER_SEC = b"worker-secret-000000000000000000"
AUTH_PUB = public_key(AUTH_SEC)
AUTH2_PUB = public_key(AUTH2_SEC)
WORKER_PUB = public_key(WORKER_SEC)
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32


def _authorities() -> AuthorityRegistry:
    reg = AuthorityRegistry()
    reg.register("op-alice", AUTH_PUB)
    reg.register("op-bob", AUTH2_PUB)
    return reg


def _quota(reg: QuotaRegistry, quota_id: str = "q-1") -> None:
    digest = compute_quota_digest(
        quota_id=quota_id,
        quota_value=400,
        measurement_window_s=3600,
        appeal_path="/appeal/quota",
    )
    sig = sign(AUTH_SEC, digest.encode("utf-8"))
    reg.register_worker("worker-1", WORKER_PUB)
    reg.issue_quota_receipt(
        quota_id=quota_id,
        quota_value=400,
        measurement_window_s=3600,
        appeal_path="/appeal/quota",
        issued_by="op-alice",
        issued_at=T0,
        signature=sig,
    )
    wsig = sign(WORKER_SEC, digest.encode("utf-8"))
    reg.acknowledge_quota(worker_id="worker-1", quota_id=quota_id, worker_signature=wsig)


class QuotaReceiptTest(unittest.TestCase):
    def test_disclosed_acknowledged_quota_allows(self) -> None:
        reg = QuotaRegistry(_authorities())
        _quota(reg)
        v = reg.quota_receipt(
            quota_id="q-1", declared_value=400, declared_window_s=3600,
            worker_id="worker-1", now=T0 + 10,
        )
        self.assertTrue(v.allowed)
        self.assertIsNone(v.deny_code)
        self.assertTrue(v.receipt_digest)

    def test_hidden_quota_denied(self) -> None:
        reg = QuotaRegistry(_authorities())
        v = reg.quota_receipt(
            quota_id="q-ghost", declared_value=400, declared_window_s=3600,
            worker_id="worker-1", now=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_HIDDEN_QUOTA)

    def test_changed_terms_denied(self) -> None:
        reg = QuotaRegistry(_authorities())
        _quota(reg)
        v = reg.quota_receipt(
            quota_id="q-1", declared_value=600, declared_window_s=3600,
            worker_id="worker-1", now=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_QUOTA_DIGEST_MISMATCH)

    def test_missing_worker_ack_denied(self) -> None:
        reg = QuotaRegistry(_authorities())
        _quota(reg)
        reg.register_worker("worker-2", public_key(b"worker-secret-000000000000000002"))
        v = reg.quota_receipt(
            quota_id="q-1", declared_value=400, declared_window_s=3600,
            worker_id="worker-2", now=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_QUOTA_ACK_MISSING)

    def test_bad_quota_signature_rejected(self) -> None:
        reg = QuotaRegistry(_authorities())
        digest = compute_quota_digest(
            quota_id="q-x", quota_value=400, measurement_window_s=3600,
            appeal_path="/appeal/quota",
        )
        with self.assertRaises(LaborAlgoError):
            reg.issue_quota_receipt(
                quota_id="q-x", quota_value=400, measurement_window_s=3600,
                appeal_path="/appeal/quota", issued_by="op-bob", issued_at=T0,
                signature=sign(AUTH_SEC, digest.encode("utf-8")),
            )


class TerminationGateTest(unittest.TestCase):
    def _pack(self, reg: TerminationRegistry) -> None:
        reg.register_evidence_pack(
            pack_id="p-1", worker_id="worker-1",
            evidence_digests=[HEX64, HEX64_B], recorded_at=T0,
        )

    def test_countersigned_termination_allows(self) -> None:
        reg = TerminationRegistry(_authorities())
        self._pack(reg)
        digest = compute_termination_digest(
            termination_id="t-1", pack_digest=reg._packs["p-1"].pack_digest,
            adjudicator_id="op-alice", adjudicated_at=T0 + 60,
        )
        reg.countersign_termination(
            termination_id="t-1", pack_id="p-1", adjudicator_id="op-alice",
            adjudicated_at=T0 + 60, signature=sign(AUTH_SEC, digest.encode("utf-8")),
        )
        v = reg.algorithmic_termination_gate(termination_id="t-1", pack_id="p-1", now=T0 + 120)
        self.assertTrue(v.allowed)

    def test_firing_without_countersign_denied(self) -> None:
        reg = TerminationRegistry(_authorities())
        self._pack(reg)
        v = reg.algorithmic_termination_gate(termination_id="t-1", pack_id="p-1", now=T0 + 120)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_ALGORITHMIC_FIRING)

    def test_unregistered_adjudicator_rejected(self) -> None:
        reg = TerminationRegistry(AuthorityRegistry())
        self._pack(reg)
        digest = compute_termination_digest(
            termination_id="t-1", pack_digest=reg._packs["p-1"].pack_digest,
            adjudicator_id="op-alice", adjudicated_at=T0 + 60,
        )
        with self.assertRaises(LaborAlgoError):
            reg.countersign_termination(
                termination_id="t-1", pack_id="p-1", adjudicator_id="op-alice",
                adjudicated_at=T0 + 60, signature=sign(AUTH_SEC, digest.encode("utf-8")),
            )


class FatigueBreakerTest(unittest.TestCase):
    def _policy(self, reg: FatigueBreaker, hours: int = 12) -> None:
        from labor_algo import compute_fatigue_policy_digest
        digest = compute_fatigue_policy_digest(
            policy_id="fb-1", max_continuous_hours=hours,
            authority_id="op-alice", pinned_at=T0,
        )
        reg.pin_policy(
            policy_id="fb-1", max_continuous_hours=hours,
            authority_id="op-alice", pinned_at=T0,
            signature=sign(AUTH_SEC, digest.encode("utf-8")),
        )

    def test_shift_under_limit_allows(self) -> None:
        brk = FatigueBreaker(_authorities())
        self._policy(brk)
        v = brk.fatigue_circuit_breaker(
            policy_id="fb-1", worker_id="worker-1", continuous_hours=11, now=T0 + 100
        )
        self.assertTrue(v.allowed)

    def test_shift_at_limit_forced_offline(self) -> None:
        brk = FatigueBreaker(_authorities())
        self._policy(brk)
        v = brk.fatigue_circuit_breaker(
            policy_id="fb-1", worker_id="worker-1", continuous_hours=12, now=T0 + 100
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_FATIGUE_CIRCUIT_BREAK)

    def test_no_policy_fails_closed(self) -> None:
        brk = FatigueBreaker(_authorities())
        v = brk.fatigue_circuit_breaker(
            policy_id="fb-missing", worker_id="worker-1", continuous_hours=2, now=T0
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_NO_FATIGUE_POLICY)


class SurveillanceGateTest(unittest.TestCase):
    def _receipt(self, reg: SurveillanceRegistry) -> None:
        from labor_algo import compute_surveillance_digest
        digest = compute_surveillance_digest(
            receipt_id="s-1", purpose="yard-safety", scope="dock-3",
            retention_days=30, biometric=False, authority_id="op-alice",
            issued_at=T0,
        )
        reg.issue_surveillance_receipt(
            receipt_id="s-1", purpose="yard-safety", scope="dock-3",
            retention_days=30, biometric=False, authority_id="op-alice",
            issued_at=T0, signature=sign(AUTH_SEC, digest.encode("utf-8")),
        )

    def test_matching_surveillance_allows(self) -> None:
        reg = SurveillanceRegistry(_authorities())
        self._receipt(reg)
        v = reg.surveillance_proportionality_gate(
            receipt_id="s-1", declared_purpose="yard-safety",
            declared_scope="dock-3", declared_biometric=False, now=T0 + 3600,
        )
        self.assertTrue(v.allowed)

    def test_purpose_reuse_denied(self) -> None:
        reg = SurveillanceRegistry(_authorities())
        self._receipt(reg)
        v = reg.surveillance_proportionality_gate(
            receipt_id="s-1", declared_purpose="productivity-scoring",
            declared_scope="dock-3", declared_biometric=False, now=T0 + 3600,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_SURVEILLANCE_PURPOSE_MISMATCH)

    def test_scope_overreach_denied(self) -> None:
        reg = SurveillanceRegistry(_authorities())
        self._receipt(reg)
        v = reg.surveillance_proportionality_gate(
            receipt_id="s-1", declared_purpose="yard-safety",
            declared_scope="all-docks", declared_biometric=False, now=T0 + 3600,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_DISPROPORTIONATE_SURVEILLANCE)

    def test_undeclared_biometric_denied(self) -> None:
        reg = SurveillanceRegistry(_authorities())
        self._receipt(reg)
        v = reg.surveillance_proportionality_gate(
            receipt_id="s-1", declared_purpose="yard-safety",
            declared_scope="dock-3", declared_biometric=True, now=T0 + 3600,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_BIOMETRIC_SURVEILLANCE_UNDECLARED)

    def test_expired_retention_denied(self) -> None:
        reg = SurveillanceRegistry(_authorities())
        self._receipt(reg)
        v = reg.surveillance_proportionality_gate(
            receipt_id="s-1", declared_purpose="yard-safety",
            declared_scope="dock-3", declared_biometric=False, now=T0 + 31 * 86400,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_SURVEILLANCE_RETENTION_EXCEEDED)


class DispatchProbeTest(unittest.TestCase):
    def _policy(self, reg: DispatchRegistry) -> None:
        from labor_algo import compute_dispatch_policy_digest
        digest = compute_dispatch_policy_digest(
            policy_id="d-1", max_rejections_per_day=4,
            authority_id="op-alice", pinned_at=T0,
        )
        reg.pin_dispatch_policy(
            policy_id="d-1", max_rejections_per_day=4,
            authority_id="op-alice", pinned_at=T0,
            signature=sign(AUTH_SEC, digest.encode("utf-8")),
        )

    def test_lawful_rejection_without_penalty_allows(self) -> None:
        reg = DispatchRegistry(_authorities())
        self._policy(reg)
        v = reg.dispatch_fairness_probe(
            policy_id="d-1", worker_id="worker-1", rejections_today=2,
            penalty_applied=False, now=T0,
        )
        self.assertTrue(v.allowed)

    def test_penalty_for_lawful_rejection_denied(self) -> None:
        reg = DispatchRegistry(_authorities())
        self._policy(reg)
        v = reg.dispatch_fairness_probe(
            policy_id="d-1", worker_id="worker-1", rejections_today=3,
            penalty_applied=True, now=T0,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_REJECTION_PENALTY)


class AVSafetyCaseTest(unittest.TestCase):
    def _case(self, reg: AVSafetyRegistry, case_id: str = "c-1") -> None:
        digest = compute_av_digest(
            case_id=case_id, vehicle_id="truck-7",
            operating_domain_digest=HEX64, authority_id="op-alice",
            issued_at=T0, expires_at=T0 + 365 * 86400,
        )
        reg.issue_safety_case(
            case_id=case_id, vehicle_id="truck-7",
            operating_domain_digest=HEX64, authority_id="op-alice",
            issued_at=T0, expires_at=T0 + 365 * 86400,
            signature=sign(AUTH_SEC, digest.encode("utf-8")),
        )

    def test_live_safety_case_allows(self) -> None:
        reg = AVSafetyRegistry(_authorities())
        self._case(reg)
        v = reg.av_safety_case_receipt(vehicle_id="truck-7", now=T0 + 3600)
        self.assertTrue(v.allowed)

    def test_no_safety_case_denied(self) -> None:
        reg = AVSafetyRegistry(_authorities())
        v = reg.av_safety_case_receipt(vehicle_id="truck-ghost", now=T0 + 3600)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_NO_SAFETY_CASE)

    def test_revoked_case_denied(self) -> None:
        reg = AVSafetyRegistry(_authorities())
        self._case(reg)
        reg.revoke_safety_case("c-1")
        v = reg.av_safety_case_receipt(vehicle_id="truck-7", now=T0 + 3600)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_AV_SAFETY_CASE_REVOKED)


class LaborImpactBindingTest(unittest.TestCase):
    def _disclosure(self, reg: LaborImpactRegistry) -> None:
        from labor_algo import compute_impact_digest
        digest = compute_impact_digest(
            deployment_id="dep-1", workers_displaced_estimate=50,
            disclosure_digest=HEX64, authority_id="op-alice", recorded_at=T0,
        )
        reg.register_impact_disclosure(
            deployment_id="dep-1", workers_displaced_estimate=50,
            disclosure_digest=HEX64, authority_id="op-alice",
            recorded_at=T0, signature=sign(AUTH_SEC, digest.encode("utf-8")),
        )

    def test_below_threshold_needs_no_disclosure(self) -> None:
        reg = LaborImpactRegistry(_authorities())
        v = reg.labor_impact_binding(deployment_id="dep-1", workers_displaced_estimate=5, now=T0)
        self.assertTrue(v.allowed)

    def test_undisclosed_displacement_denied(self) -> None:
        reg = LaborImpactRegistry(_authorities())
        v = reg.labor_impact_binding(deployment_id="dep-1", workers_displaced_estimate=50, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, DENY_LABOR_IMPACT_UNDISCLOSED)

    def test_disclosed_displacement_allows(self) -> None:
        reg = LaborImpactRegistry(_authorities())
        self._disclosure(reg)
        v = reg.labor_impact_binding(deployment_id="dep-1", workers_displaced_estimate=50, now=T0 + 10)
        self.assertTrue(v.allowed)

    def test_audit_event_shape(self) -> None:
        evt = labor_audit_event("labor.quota_disclosed", quota_id="q-1")
        self.assertEqual(evt["event"], "labor.quota_disclosed")
        self.assertEqual(evt["domain"], "labor")
        self.assertEqual(evt["quota_id"], "q-1")


if __name__ == "__main__":
    unittest.main()
