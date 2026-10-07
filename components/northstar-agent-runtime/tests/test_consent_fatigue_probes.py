"""Tests for the consent-fatigue extension in approval_fatigue_probes.

Covers the consent-surface probe family, FatigueMeter (continuous
per-axis measurement), and FatigueResistantGate (named dispositions
with fixed-vocabulary reasons).
"""

from __future__ import annotations

import unittest

from approval_fatigue_probes import (
    APPROVAL_FATIGUE_BENIGN,
    APPROVAL_FATIGUE_PROBES,
    APPROVAL_FATIGUE_SOURCE,
    CONSENT_SURFACE_FAMILY,
    DISPOSITION_DENY,
    DISPOSITION_HOLD_SECOND_APPROVER,
    DISPOSITION_RECORD,
    DISPOSITION_REQUIRE_JUSTIFICATION,
    DISPOSITION_ROTATE_APPROVER,
    GATE_REASONS,
    RISK_HIGH,
    RISK_LOW,
    VERDICT_FATIGUED,
    VERDICT_FLOODED,
    VERDICT_HEALTHY,
    ApprovalEvent,
    FatigueMeter,
    FatigueMonitor,
    FatigueResistantGate,
    probe_by_name,
    probes_by_family,
    verify_decision,
    verify_measurement,
)

NEW_ATTACKS = (
    "dialog-stacking",
    "approve-all-bundling",
    "evidence-burial",
    "default-opt-in",
)
NEW_BENIGN = ("benign-position-randomized",)

DENY_KEYWORDS = (
    "deny", "denies", "denied", "refus", "reject", "fail",
    "held", "quarantine", "escalat", "throttl",
)


def _ev(t: float, approved: bool = True, approver: str = "oncall") -> ApprovalEvent:
    return ApprovalEvent(approver=approver, decided_at=t, approved=approved)


class ConsentSurfaceCorpusTest(unittest.TestCase):
    def test_family_registered(self):
        self.assertIn(CONSENT_SURFACE_FAMILY, APPROVAL_FATIGUE_SOURCE["families"])
        self.assertEqual(CONSENT_SURFACE_FAMILY, "consent-surface")
        self.assertEqual(len(probes_by_family(CONSENT_SURFACE_FAMILY)), 4)

    def test_new_probes_deny_benign_allows(self):
        for name in NEW_ATTACKS:
            p = probe_by_name(name)
            self.assertEqual(p["expected"], "deny", name)
        self.assertEqual(probe_by_name(NEW_BENIGN[0])["expected"], "allow")

    def test_new_attacks_name_deny_side_mechanism(self):
        for name in NEW_ATTACKS:
            gi = probe_by_name(name)["gate_interaction"].lower()
            self.assertTrue(
                any(k in gi for k in DENY_KEYWORDS),
                f"{name}: gate_interaction names no deny-side mechanism",
            )

    def test_new_probe_fields_complete(self):
        for name in (*NEW_ATTACKS, *NEW_BENIGN):
            p = probe_by_name(name)
            for field in ("probe", "family", "attack", "gate_interaction", "expected", "reason"):
                self.assertIn(field, p, name)
                self.assertTrue(p[field], f"{name}.{field}")
            self.assertEqual(p["family"], CONSENT_SURFACE_FAMILY)

    def test_names_unique_across_full_corpus(self):
        attack_names = [p["probe"] for p in APPROVAL_FATIGUE_PROBES]
        benign_names = [p["probe"] for p in APPROVAL_FATIGUE_BENIGN]
        self.assertEqual(len(attack_names), len(set(attack_names)))
        self.assertEqual(
            len(set(attack_names) | set(benign_names)),
            len(attack_names) + len(benign_names),
        )
        for name in NEW_ATTACKS:
            self.assertIn(name, attack_names)
        for name in NEW_BENIGN:
            self.assertIn(name, benign_names)

    def test_source_lists_cover_new_probes(self):
        self.assertTrue(
            set(NEW_ATTACKS) <= set(APPROVAL_FATIGUE_SOURCE["probes"])
        )
        self.assertTrue(
            set(NEW_BENIGN) <= set(APPROVAL_FATIGUE_SOURCE["benign"])
        )

    def test_probe_by_name_miss(self):
        with self.assertRaises(KeyError):
            probe_by_name("no-such-consent-probe")


class FatigueMeterTest(unittest.TestCase):
    def test_empty_trajectory_measures_zero(self):
        m = FatigueMeter().measure((), 900.0)
        self.assertEqual(m["velocity_ratio"], 0.0)
        self.assertEqual(m["streak_ratio"], 0.0)
        self.assertEqual(m["collapse_ratio"], 0.0)
        self.assertEqual(m["denial_decay"], 0.0)
        self.assertEqual(m["fatigue_index"], 0.0)
        self.assertTrue(verify_measurement(m))

    def test_velocity_ratio(self):
        events = tuple(_ev(i * 100.0) for i in range(6))  # 6 approvals
        m = FatigueMeter().measure(events, 900.0)
        self.assertAlmostEqual(m["velocity_ratio"], 6 / 12)

    def test_streak_ratio_trailing(self):
        events = tuple(_ev(i * 30.0) for i in range(25))  # 25 straight approvals
        m = FatigueMeter().measure(events, 900.0)
        self.assertAlmostEqual(m["streak_ratio"], 1.0)
        # A denial resets the trailing streak even mid-window.
        mixed = events[:20] + (_ev(630.0, approved=False),) + events[21:]
        m2 = FatigueMeter().measure(mixed, 900.0)
        self.assertAlmostEqual(m2["streak_ratio"], 4 / 25)

    def test_collapse_ratio(self):
        events = tuple(_ev(t) for t in (0.0, 45.0, 57.0, 60.0))
        m = FatigueMeter().measure(events, 900.0)
        self.assertAlmostEqual(m["collapse_ratio"], 1 / 3)

    def test_denial_decay_full(self):
        # Baseline half denies at 50%; recent half never denies.
        events = (
            tuple(_ev(t, approved=(i % 2 == 0)) for i, t in enumerate((10.0, 60.0, 110.0, 160.0)))
            + tuple(_ev(t) for t in (500.0, 560.0, 620.0, 680.0))
        )
        m = FatigueMeter().measure(events, 900.0)
        self.assertAlmostEqual(m["denial_decay"], 1.0)

    def test_denial_decay_no_baseline_is_zero(self):
        events = tuple(_ev(t) for t in (500.0, 560.0, 620.0, 680.0))
        m = FatigueMeter().measure(events, 900.0)
        self.assertEqual(m["denial_decay"], 0.0)

    def test_denial_decay_empty_recent_half_is_zero(self):
        # All events in the baseline half: inactivity, not decay.
        events = tuple(_ev(t, approved=(i % 2 == 0)) for i, t in enumerate((10.0, 60.0, 110.0, 160.0)))
        m = FatigueMeter().measure(events, 900.0)
        self.assertEqual(m["denial_decay"], 0.0)

    def test_index_is_max_of_axes(self):
        events = tuple(_ev(i * 100.0) for i in range(6))
        m = FatigueMeter().measure(events, 900.0)
        axes = (m["velocity_ratio"], m["streak_ratio"], m["collapse_ratio"], m["denial_decay"])
        self.assertAlmostEqual(m["fatigue_index"], min(1.0, max(axes)))

    def test_index_clamps_above_one(self):
        events = tuple(_ev(i * 60.0) for i in range(13))  # velocity 13/12 > 1
        m = FatigueMeter().measure(events, 900.0)
        self.assertGreater(m["velocity_ratio"], 1.0)
        self.assertEqual(m["fatigue_index"], 1.0)

    def test_measurement_digest_round_trip(self):
        events = tuple(_ev(i * 100.0) for i in range(4))
        m = FatigueMeter().measure(events, 900.0)
        self.assertTrue(verify_measurement(m))

    def test_measurement_tamper_detected(self):
        events = tuple(_ev(i * 100.0) for i in range(4))
        m = FatigueMeter().measure(events, 900.0)
        tampered = dict(m)
        tampered["velocity_ratio"] = 0.0
        self.assertFalse(verify_measurement(tampered))

    def test_measurement_malformed(self):
        self.assertFalse(verify_measurement({}))
        self.assertFalse(verify_measurement({"digest": "nope"}))

    def test_meter_config_validation(self):
        with self.assertRaises(ValueError):
            FatigueMeter(window_seconds=0)
        with self.assertRaises(ValueError):
            FatigueMeter(max_approvals_per_window=0)
        with self.assertRaises(ValueError):
            FatigueMeter(uniform_approve_streak=1)
        with self.assertRaises(ValueError):
            FatigueMeter(min_deliberation_seconds=-1)
        with self.assertRaises(ValueError):
            FatigueMeter(alert_threshold=0.0)
        with self.assertRaises(ValueError):
            FatigueMeter(alert_threshold=1.5)


class FatigueResistantGateTest(unittest.TestCase):
    def setUp(self):
        self.gate = FatigueResistantGate()

    def test_healthy_trajectory_records(self):
        events = (
            _ev(0.0), _ev(100.0), _ev(200.0, approved=False),
            _ev(300.0), _ev(400.0),
        )
        d = self.gate.decide(events, 900.0)
        self.assertEqual(d["disposition"], DISPOSITION_RECORD)
        self.assertEqual(tuple(d["reasons"]), ("healthy-trajectory",))
        self.assertEqual(d["verdict"], VERDICT_HEALTHY)
        self.assertTrue(verify_decision(d))

    def test_early_warning_requires_justification(self):
        # Healthy verdict, but denial decay pushes the index past the alert
        # threshold: the approver used to deny and stopped.
        events = (
            tuple(_ev(t, approved=(i % 2 == 0)) for i, t in enumerate((10.0, 60.0, 110.0, 160.0)))
            + tuple(_ev(t) for t in (500.0, 560.0, 620.0, 680.0))
        )
        d = self.gate.decide(events, 900.0)
        self.assertEqual(d["verdict"], VERDICT_HEALTHY)
        self.assertGreaterEqual(d["fatigue_index"], 0.7)
        self.assertEqual(d["disposition"], DISPOSITION_REQUIRE_JUSTIFICATION)
        self.assertIn("index-above-threshold", d["reasons"])

    def test_flooded_low_risk_holds_for_second_approver(self):
        events = tuple(_ev(i * 70.0) for i in range(13))
        d = self.gate.decide(events, 900.0)
        self.assertEqual(d["verdict"], VERDICT_FLOODED)
        self.assertEqual(d["disposition"], DISPOSITION_HOLD_SECOND_APPROVER)
        self.assertIn("flooded-intake", d["reasons"])

    def test_flooded_high_risk_denies(self):
        events = tuple(_ev(i * 70.0) for i in range(13))
        d = self.gate.decide(events, 900.0, risk_tier=RISK_HIGH)
        self.assertEqual(d["disposition"], DISPOSITION_DENY)
        self.assertIn("flooded-intake", d["reasons"])
        self.assertIn("high-stakes-during-fatigue", d["reasons"])

    def test_fatigued_collapse_rotates_approver(self):
        events = tuple(_ev(t) for t in (0.0, 9.0, 18.0, 27.0, 28.5))
        d = self.gate.decide(events, 900.0)
        self.assertEqual(d["verdict"], VERDICT_FATIGUED)
        self.assertEqual(d["disposition"], DISPOSITION_ROTATE_APPROVER)
        self.assertIn("fatigued-approver", d["reasons"])
        self.assertIn("interval-collapse", d["reasons"])

    def test_fatigued_high_risk_denies(self):
        events = tuple(_ev(t) for t in (0.0, 9.0, 18.0, 27.0, 28.5))
        d = self.gate.decide(events, 900.0, risk_tier=RISK_HIGH)
        self.assertEqual(d["disposition"], DISPOSITION_DENY)
        self.assertIn("high-stakes-during-fatigue", d["reasons"])

    def test_request_ref_carried(self):
        d = self.gate.decide((), 900.0, request_ref="req-123")
        self.assertEqual(d["request_ref"], "req-123")
        self.assertTrue(verify_decision(d))

    def test_bad_risk_tier_raises(self):
        with self.assertRaises(ValueError):
            self.gate.decide((), 900.0, risk_tier="medium")

    def test_reasons_from_fixed_vocabulary(self):
        cases = [
            ((), 900.0, RISK_LOW),
            (tuple(_ev(i * 70.0) for i in range(13)), 900.0, RISK_LOW),
            (tuple(_ev(i * 70.0) for i in range(13)), 900.0, RISK_HIGH),
            (tuple(_ev(t) for t in (0.0, 9.0, 18.0, 27.0, 28.5)), 900.0, RISK_LOW),
            (tuple(_ev(t) for t in (0.0, 9.0, 18.0, 27.0, 28.5)), 900.0, RISK_HIGH),
        ]
        for events, now, tier in cases:
            d = self.gate.decide(events, now, risk_tier=tier)
            for r in d["reasons"]:
                self.assertIn(r, GATE_REASONS, f"reason {r!r} not in fixed vocabulary")

    def test_decision_tamper_detected(self):
        d = self.gate.decide((), 900.0)
        tampered = dict(d)
        tampered["disposition"] = DISPOSITION_RECORD if d["disposition"] != DISPOSITION_RECORD else DISPOSITION_DENY
        self.assertFalse(verify_decision(tampered))

    def test_decision_unknown_disposition_fails(self):
        d = self.gate.decide((), 900.0)
        forged = dict(d)
        forged["disposition"] = "auto_approve"
        forged["digest"] = "sha256:" + "0" * 64  # well-formed shape, unknown disposition
        self.assertFalse(verify_decision(forged))

    def test_decision_unknown_reason_fails(self):
        d = self.gate.decide((), 900.0)
        forged = dict(d)
        forged["reasons"] = ("healthy-trajectory", "vibes")
        self.assertFalse(verify_decision(forged))

    def test_custom_monitor_and_meter_compose(self):
        gate = FatigueResistantGate(
            monitor=FatigueMonitor(max_approvals_per_window=100),
            meter=FatigueMeter(max_approvals_per_window=100),
        )
        events = tuple(_ev(i * 70.0) for i in range(13))
        d = gate.decide(events, 900.0)
        # 13 approvals no longer floods a bound of 100: healthy, records.
        self.assertEqual(d["verdict"], VERDICT_HEALTHY)
        self.assertEqual(d["disposition"], DISPOSITION_RECORD)


if __name__ == "__main__":
    unittest.main()
