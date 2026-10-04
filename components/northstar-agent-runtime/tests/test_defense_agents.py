"""Tests for defense_agents.py (one-hundred-sixty-fifth batch)."""

import dataclasses
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ed25519 import public_key

import defense_agents as d

T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
SEC = b"defense-test-" + b"0" * 19  # 32 bytes
assert len(SEC) == 32


def _review(deliberation=300, min_delib=180, reviewed_at=T0, expires_at=T0 + 86400,
            output_digest=HEX64):
    return d.human_review_receipt(
        receipt_id="hr-1", output_id="out-1", output_digest=output_digest,
        reviewer_id="cmdr-1", review_basis_digest=HEX64_B,
        min_deliberation_s=min_delib, deliberation_s=deliberation,
        reviewed_at=reviewed_at, expires_at=expires_at,
        authority_secret=SEC)


def _intel(revalidated_at=0, collected_at=T0 - 3600, window=7200):
    return d.intel_receipt(
        receipt_id="ir-1", intel_id="tgt-1", collected_at=collected_at,
        revalidated_at=revalidated_at, source_chain_digest=HEX64,
        freshness_window_s=window, bound_at=T0, authority_secret=SEC)


def _reliance(total=100, accepted=70, delib=30000):
    return d.reliance_report(
        receipt_id="rr-1", window_id="w-1", decisions_total=total,
        ai_accepted=accepted, deliberation_total_s=delib,
        declared_at=T0, authority_secret=SEC)


def _posture(staff=5, floor=4):
    return d.protection_posture(
        receipt_id="pp-1", unit_id="cp-cell", declared_staff=staff,
        required_min_staff=floor, declared_at=T0, authority_secret=SEC)


def _redline(removal=False, disclosure=""):
    return d.redline_contract(
        receipt_id="rc-1", vendor_id="vendor-1", contract_id="c-1",
        redlines=("no_full_autonomous_lethal",),
        removal_requested=removal, removal_disclosure_digest=disclosure,
        bound_at=T0, authority_secret=SEC)


def _intel_report(watermark=HEX64, assertions=(("a1", HEX64), ("a2", HEX64_B)),
                  ai=True):
    return d.intel_report(
        receipt_id="irep-1", report_id="rep-1", ai_generated=ai,
        watermark_digest=watermark, assertions=assertions,
        issued_at=T0, authority_secret=SEC)


def _ladder(locked=True, levels=3, passed_at=T0, window=30 * 86400):
    return d.escalation_ladder_config(
        receipt_id="el-1", ladder_id="ladder-1", nuclear_option_locked=locked,
        authorization_levels=levels, cooldown_s=3600,
        regression_test_id="reg-1", regression_passed_at=passed_at,
        regression_window_s=window, bound_at=T0, authority_secret=SEC)


def _regression(n_sims=100, nuke=10):
    return d.escalation_regression(
        receipt_id="er-1", test_id="reg-1", ladder_id="ladder-1",
        n_sims=n_sims, nuke_deployed_sims=nuke, completed_at=T0,
        authority_secret=SEC)


def _cycle(baseline=86400 * 7, current=3600, ack=""):
    return d.decision_cycle(
        receipt_id="dc-1", cycle_id="cycle-1", baseline_cycle_s=baseline,
        current_cycle_s=current, commander_ack_digest=ack,
        observed_at=T0, authority_secret=SEC)


def _cutoff(notified_at=T0, cutoff_at=T0 + 86400):
    return d.vendor_cutoff_notice(
        receipt_id="vc-1", vendor_id="vendor-1", system_id="sys-1",
        notified_at=notified_at, cutoff_at=cutoff_at,
        transition_clock_s=86400 * 30, authority_secret=SEC)


def _treaty(effective=T0 - 86400, updated=T0, review_due=T0 + 86400 * 30):
    return d.treaty_position(
        receipt_id="tp-1", treaty_id="ccw-2026", position_digest=HEX64,
        effective_at=effective, constraints_updated_at=updated,
        review_due_at=review_due, bound_at=T0, authority_secret=SEC)


def _swarm(operators=4, platforms=16, changelog=HEX64):
    return d.swarm_config(
        receipt_id="sc-1", swarm_id="swarm-1", operators=operators,
        platforms=platforms, confidence_threshold=0.75,
        threshold_changelog_digest=changelog, declared_at=T0,
        authority_secret=SEC)


class HumanReviewTest(unittest.TestCase):
    def test_substantive_review_allows(self):
        v = d.check_human_review(_review(), HEX64, T0 + 100)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_checkbox_review_denies(self):
        v = d.check_human_review(_review(deliberation=5), HEX64, T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("defense.checkbox_review", v.reason)

    def test_no_review_denies(self):
        v = d.check_human_review(None, HEX64, T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("defense.rubber_stamp", v.reason)

    def test_expired_review_denies(self):
        v = d.check_human_review(_review(), HEX64, T0 + 86401)
        self.assertFalse(v.allowed)
        self.assertIn("defense.stale_review", v.reason)

    def test_review_digest_mismatch_denies(self):
        v = d.check_human_review(_review(), HEX64_B, T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("defense.review_mismatch", v.reason)

    def test_tampered_review_denies(self):
        # ed25519.verify() returns a bool and never raises: a tampered
        # payload must not slip through a try/except.
        forged = dataclasses.replace(_review(), output_digest=HEX64_B)
        v = d.check_human_review(forged, HEX64_B, T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("defense.unsigned_review", v.reason)


class IntelFreshnessTest(unittest.TestCase):
    def test_fresh_intel_allows(self):
        v = d.check_intel_freshness(_intel(), T0)
        self.assertTrue(v.allowed)

    def test_stale_intel_denies(self):
        v = d.check_intel_freshness(_intel(collected_at=T0 - 7201), T0)
        self.assertFalse(v.allowed)
        self.assertIn("defense.stale_intel", v.reason)

    def test_revalidation_refreshes_window(self):
        v = d.check_intel_freshness(
            _intel(collected_at=T0 - 7000, revalidated_at=T0 - 60), T0)
        self.assertTrue(v.allowed)

    def test_no_provenance_denies(self):
        v = d.check_intel_freshness(None, T0)
        self.assertFalse(v.allowed)
        self.assertIn("defense.no_intel_provenance", v.reason)


class AutomationBiasTest(unittest.TestCase):
    def test_normal_reliance_allows(self):
        v = d.automation_bias_probe(_reliance())
        self.assertTrue(v.allowed)

    def test_rubber_stamp_pattern_denies(self):
        v = d.automation_bias_probe(_reliance(total=100, accepted=98, delib=300))
        self.assertFalse(v.allowed)
        self.assertIn("defense.automation_bias", v.reason)

    def test_empty_window_allows(self):
        v = d.automation_bias_probe(_reliance(total=0, accepted=0, delib=0))
        self.assertTrue(v.allowed)


class ProtectionFloorTest(unittest.TestCase):
    def test_floor_met_allows(self):
        v = d.check_protection_floor(_posture())
        self.assertTrue(v.allowed)

    def test_below_floor_denies(self):
        v = d.check_protection_floor(_posture(staff=1, floor=4))
        self.assertFalse(v.allowed)
        self.assertIn("defense.protection_floor_breach", v.reason)


class RedlineContractTest(unittest.TestCase):
    def test_intact_redlines_allow(self):
        v = d.check_redline_contract(_redline())
        self.assertTrue(v.allowed)

    def test_silent_removal_denies(self):
        v = d.check_redline_contract(_redline(removal=True))
        self.assertFalse(v.allowed)
        self.assertIn("defense.silent_redline_removal", v.reason)

    def test_disclosed_removal_allows(self):
        v = d.check_redline_contract(_redline(removal=True, disclosure=HEX64))
        self.assertTrue(v.allowed)


class IntelReportTest(unittest.TestCase):
    def test_evidence_bound_report_allows(self):
        v = d.check_intel_report(_intel_report())
        self.assertTrue(v.allowed)

    def test_unwatermarked_ai_report_denies(self):
        v = d.check_intel_report(_intel_report(watermark=""))
        self.assertFalse(v.allowed)
        self.assertIn("defense.unwatermarked_ai_intel", v.reason)

    def test_evidence_free_assertion_denies(self):
        v = d.check_intel_report(_intel_report(assertions=(("a1", HEX64), ("a2", ""))))
        self.assertFalse(v.allowed)
        self.assertIn("defense.unverified_assertion", v.reason)


class EscalationLadderTest(unittest.TestCase):
    def test_locked_fresh_ladder_allows(self):
        v = d.check_escalation_ladder(_ladder(), T0 + 100)
        self.assertTrue(v.allowed)

    def test_unlocked_nuclear_denies(self):
        v = d.check_escalation_ladder(_ladder(locked=False), T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("defense.nuclear_unlocked", v.reason)

    def test_overdue_regression_denies(self):
        v = d.check_escalation_ladder(_ladder(passed_at=T0 - 31 * 86400),
                                     T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("defense.escalation_test_overdue", v.reason)

    def test_high_nuke_fraction_fails_regression(self):
        v = d.check_escalation_regression(_regression(nuke=95))
        self.assertFalse(v.allowed)
        self.assertIn("defense.escalation_regression_failed", v.reason)

    def test_low_nuke_fraction_passes_regression(self):
        v = d.check_escalation_regression(_regression())
        self.assertTrue(v.allowed)


class DecisionCompressionTest(unittest.TestCase):
    def test_below_ratio_allows(self):
        v = d.check_decision_compression(_cycle(baseline=86400, current=36000))
        self.assertTrue(v.allowed)

    def test_unacknowledged_compression_denies(self):
        v = d.check_decision_compression(_cycle(baseline=86400 * 7, current=3600))
        self.assertFalse(v.allowed)
        self.assertIn("defense.compression_unacknowledged", v.reason)


class VendorCutoffTest(unittest.TestCase):
    def test_no_cutoff_allows(self):
        v = d.check_vendor_cutoff(None, T0)
        self.assertTrue(v.allowed)

    def test_silent_effective_cutoff_denies(self):
        v = d.check_vendor_cutoff(_cutoff(notified_at=0, cutoff_at=T0 - 1), T0)
        self.assertFalse(v.allowed)
        self.assertIn("defense.silent_vendor_cutoff", v.reason)


class TreatyPositionTest(unittest.TestCase):
    def test_current_position_allows(self):
        v = d.check_treaty_position(_treaty(), T0 + 100)
        self.assertTrue(v.allowed)

    def test_drift_denies(self):
        v = d.check_treaty_position(_treaty(updated=T0 - 100 * 86400), T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("defense.treaty_drift", v.reason)

    def test_overdue_review_denies(self):
        v = d.check_treaty_position(
            _treaty(review_due=T0 - 1), T0 + 100)
        self.assertFalse(v.allowed)
        self.assertIn("defense.treaty_review_overdue", v.reason)


class SwarmConfigTest(unittest.TestCase):
    def test_quantified_command_allows(self):
        v = d.check_swarm_config(_swarm())
        self.assertTrue(v.allowed)

    def test_no_operator_denies(self):
        v = d.check_swarm_config(_swarm(operators=0, platforms=4))
        self.assertFalse(v.allowed)
        self.assertIn("defense.no_operator_command", v.reason)

    def test_ratio_breach_denies(self):
        v = d.check_swarm_config(_swarm(operators=1, platforms=64))
        self.assertFalse(v.allowed)
        self.assertIn("defense.command_ratio_breach", v.reason)

    def test_missing_changelog_denies(self):
        v = d.check_swarm_config(_swarm(changelog=""))
        self.assertFalse(v.allowed)
        self.assertIn("defense.threshold_drift", v.reason)


class StructuralTest(unittest.TestCase):
    def test_malformed_receipt_raises_not_verdict(self):
        with self.assertRaises(d.DefenseError):
            d.human_review_receipt(
                receipt_id="x", output_id="o", output_digest="zz",
                reviewer_id="r", review_basis_digest=HEX64,
                min_deliberation_s=10, deliberation_s=10,
                reviewed_at=T0, expires_at=T0 + 10,
                authority_secret=SEC)

    def test_unknown_redline_kind_raises(self):
        with self.assertRaises(d.DefenseError):
            d.redline_contract(
                receipt_id="x", vendor_id="v", contract_id="c",
                redlines=("no_drone_strikes",), removal_requested=False,
                bound_at=T0, authority_secret=SEC)


if __name__ == "__main__":
    unittest.main()
