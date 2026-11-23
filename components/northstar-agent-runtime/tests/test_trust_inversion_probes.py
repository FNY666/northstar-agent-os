"""Tests for trust_inversion_probes: corpus shape, culture assessment, calibration."""
import unittest

import trust_inversion_probes as tip

EXPECTED_ATTACK_PROBES = (
    "comfort-laundering",
    "familiarity-credential",
    "success-streak-bypass",
    "overtrust-delegation-handoff",
    "scrutiny-collapse",
    "delegation-drift",
    "rubber-stamp-cascade",
    "comfort-gated-weakening",
    "static-gate-in-high-comfort",
    "threshold-erosion",
)

EXPECTED_BENIGN_PROBES = (
    "benign-high-comfort-high-gate",
    "benign-calibrated-delegation",
    "benign-comfort-reset-after-incident",
)

REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")

# Every attack probe's gate interaction must name an active deny-side
# check -- framing the attack must never read as a defense.
DENY_SIDE_KEYWORDS = (
    "denies",
    "denied",
    "deny",
    "refuses",
    "blocks",
    "held",
    "never",
    "fail closed",
    "fail-closes",
)


def _signals(**kwargs) -> "tip.ComfortSignals":
    params = {
        "window_id": "w1",
        "delegation_rate": 0.5,
        "scrutiny_rate": 0.8,
        "rubber_stamp_rate": 0.1,
        "approval_median_latency_s": 60.0,
        "override_rate": 0.1,
        "agent_tenure_runs": 100,
        "success_streak": 10,
    }
    params.update(kwargs)
    return tip.build_signals(**params)


class CorpusShapeTests(unittest.TestCase):
    def test_attack_probe_names(self) -> None:
        self.assertEqual(tip.attack_probe_names(), EXPECTED_ATTACK_PROBES)

    def test_benign_probe_names(self) -> None:
        self.assertEqual(tip.benign_probe_names(), EXPECTED_BENIGN_PROBES)

    def test_required_keys(self) -> None:
        for probe in (*tip.TRUST_INVERSION_PROBES, *tip.TRUST_INVERSION_BENIGN):
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, probe["probe"])

    def test_unique_names(self) -> None:
        names = [*tip.attack_probe_names(), *tip.benign_probe_names()]
        self.assertEqual(len(names), len(set(names)))

    def test_expected_outcomes(self) -> None:
        outcomes = tip.expected_outcomes()
        for name in EXPECTED_ATTACK_PROBES:
            self.assertEqual(outcomes[name], "deny", name)
        for name in EXPECTED_BENIGN_PROBES:
            self.assertEqual(outcomes[name], "allow", name)

    def test_deny_side_keyword(self) -> None:
        for probe in tip.TRUST_INVERSION_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} has no deny-side keyword",
            )

    def test_per_family_counts(self) -> None:
        counts = {
            fam: len(tip.probes_in_family(fam))
            for fam in ("inversion-exploit", "delegation-culture", "gate-strength", "benign")
        }
        self.assertEqual(
            counts,
            {
                "inversion-exploit": 4,
                "delegation-culture": 3,
                "gate-strength": 3,
                "benign": 3,
            },
        )

    def test_probe_by_name_and_keyerror(self) -> None:
        self.assertEqual(
            tip.probe_by_name("comfort-laundering")["expected"], "deny"
        )
        self.assertEqual(
            tip.probe_by_name("benign-calibrated-delegation")["expected"], "allow"
        )
        with self.assertRaises(KeyError):
            tip.probe_by_name("no-such-probe")


class ComfortSignalsTests(unittest.TestCase):
    def test_round_trip_digest(self) -> None:
        record = _signals()
        self.assertTrue(record.digest.startswith("sha256:"))
        self.assertTrue(tip.verify_signals(record))

    def test_tampered_digest_fails(self) -> None:
        record = _signals()
        tampered = tip.ComfortSignals(
            window_id=record.window_id,
            delegation_rate=0.99,  # different value, same digest
            scrutiny_rate=record.scrutiny_rate,
            rubber_stamp_rate=record.rubber_stamp_rate,
            approval_median_latency_s=record.approval_median_latency_s,
            override_rate=record.override_rate,
            agent_tenure_runs=record.agent_tenure_runs,
            success_streak=record.success_streak,
            digest=record.digest,
        )
        self.assertFalse(tip.verify_signals(tampered))

    def test_bad_inputs_rejected(self) -> None:
        with self.assertRaises(tip.TrustInversionError):
            _signals(delegation_rate=1.5)
        with self.assertRaises(tip.TrustInversionError):
            _signals(scrutiny_rate=-0.1)
        with self.assertRaises(tip.TrustInversionError):
            _signals(agent_tenure_runs=-1)
        with self.assertRaises(tip.TrustInversionError):
            _signals(approval_median_latency_s=-5.0)
        with self.assertRaises(tip.TrustInversionError):
            _signals(window_id="  ")

    def test_none_latency_allowed(self) -> None:
        record = _signals(approval_median_latency_s=None)
        self.assertIsNone(record.approval_median_latency_s)
        self.assertTrue(tip.verify_signals(record))


class ComfortIndexTests(unittest.TestCase):
    def test_bounds(self) -> None:
        low = _signals(
            delegation_rate=0.0, scrutiny_rate=1.0,
            rubber_stamp_rate=0.0, override_rate=1.0,
        )
        self.assertEqual(tip.comfort_index(low), 0.0)
        high = _signals(
            delegation_rate=1.0, scrutiny_rate=0.0,
            rubber_stamp_rate=1.0, override_rate=0.0,
        )
        self.assertEqual(tip.comfort_index(high), 1.0)

    def test_monotone_in_delegation(self) -> None:
        a = tip.comfort_index(_signals(delegation_rate=0.2))
        b = tip.comfort_index(_signals(delegation_rate=0.8))
        self.assertLess(a, b)


class CultureAssessmentTests(unittest.TestCase):
    def test_healthy_window(self) -> None:
        ok, findings = tip.assess_delegation_culture(_signals())
        self.assertTrue(ok)
        self.assertEqual(findings, ())

    def test_scrutiny_collapsed(self) -> None:
        ok, findings = tip.assess_delegation_culture(_signals(scrutiny_rate=0.1))
        self.assertFalse(ok)
        self.assertIn("scrutiny_collapsed", findings)

    def test_delegation_unbounded(self) -> None:
        ok, findings = tip.assess_delegation_culture(_signals(delegation_rate=0.95))
        self.assertFalse(ok)
        self.assertIn("delegation_unbounded", findings)

    def test_rubber_stamp_cascade(self) -> None:
        ok, findings = tip.assess_delegation_culture(_signals(rubber_stamp_rate=0.8))
        self.assertFalse(ok)
        self.assertIn("rubber_stamp_cascade", findings)

    def test_tenure_overtrust(self) -> None:
        ok, findings = tip.assess_delegation_culture(
            _signals(agent_tenure_runs=5000, scrutiny_rate=0.3)
        )
        self.assertFalse(ok)
        self.assertIn("tenure_overtrust", findings)

    def test_streak_overtrust(self) -> None:
        ok, findings = tip.assess_delegation_culture(
            _signals(success_streak=120, scrutiny_rate=0.3)
        )
        self.assertFalse(ok)
        self.assertIn("streak_overtrust", findings)

    def test_high_scrutiny_suppresses_tenure_findings(self) -> None:
        ok, findings = tip.assess_delegation_culture(
            _signals(agent_tenure_runs=5000, success_streak=120, scrutiny_rate=0.9)
        )
        self.assertNotIn("tenure_overtrust", findings)
        self.assertNotIn("streak_overtrust", findings)

    def test_findings_in_fixed_vocabulary(self) -> None:
        _, findings = tip.assess_delegation_culture(
            _signals(
                delegation_rate=0.99, scrutiny_rate=0.0, rubber_stamp_rate=0.9,
                agent_tenure_runs=9999, success_streak=999,
            )
        )
        for finding in findings:
            self.assertIn(finding, tip.CULTURE_FINDINGS)


class CalibrationTests(unittest.TestCase):
    def test_inverse_coupling(self) -> None:
        base = 0.4
        low_comfort = tip.calibrate_gate_strength(_signals(), base_strength=base)
        high_comfort = tip.calibrate_gate_strength(
            _signals(
                delegation_rate=0.95, scrutiny_rate=0.1,
                rubber_stamp_rate=0.8, override_rate=0.0,
            ),
            base_strength=base,
        )
        self.assertGreater(
            high_comfort.required_strength, low_comfort.required_strength
        )
        # Higher comfort never lowers the requirement.
        self.assertGreaterEqual(high_comfort.required_strength, base)

    def test_strengthen_disposition(self) -> None:
        decision = tip.calibrate_gate_strength(
            _signals(delegation_rate=0.9, scrutiny_rate=0.2, rubber_stamp_rate=0.6),
            base_strength=0.3,
        )
        self.assertEqual(decision.disposition, "strengthen")
        self.assertEqual(decision.reason, "comfort-raised-the-bar")

    def test_hold_disposition(self) -> None:
        # Near-zero comfort: the lift band is not crossed, so the gate holds.
        quiet = _signals(
            delegation_rate=0.05, scrutiny_rate=1.0,
            rubber_stamp_rate=0.0, override_rate=1.0,
        )
        self.assertLessEqual(tip.comfort_index(quiet), 0.05)
        decision = tip.calibrate_gate_strength(quiet, base_strength=0.5)
        self.assertEqual(decision.disposition, "hold")
        self.assertEqual(decision.reason, "strength-matches-comfort")

    def test_escalate_extreme_comfort_high_stakes(self) -> None:
        decision = tip.calibrate_gate_strength(
            _signals(
                delegation_rate=1.0, scrutiny_rate=0.0,
                rubber_stamp_rate=1.0, override_rate=0.0,
            ),
            base_strength=0.5,
            stakes="high",
        )
        self.assertEqual(decision.disposition, "escalate")
        self.assertEqual(decision.reason, "extreme-comfort-high-stakes")

    def test_extreme_comfort_low_stakes_does_not_escalate(self) -> None:
        decision = tip.calibrate_gate_strength(
            _signals(
                delegation_rate=1.0, scrutiny_rate=0.0,
                rubber_stamp_rate=1.0, override_rate=0.0,
            ),
            base_strength=0.5,
            stakes="low",
        )
        self.assertNotEqual(decision.disposition, "escalate")

    def test_required_strength_clamped(self) -> None:
        decision = tip.calibrate_gate_strength(
            _signals(
                delegation_rate=1.0, scrutiny_rate=0.0,
                rubber_stamp_rate=1.0, override_rate=0.0,
            ),
            base_strength=0.9,
        )
        self.assertLessEqual(decision.required_strength, 1.0)

    def test_decision_digest_round_trip(self) -> None:
        decision = tip.calibrate_gate_strength(_signals(), base_strength=0.4)
        self.assertTrue(decision.digest.startswith("sha256:"))
        self.assertTrue(tip.verify_decision(decision))

    def test_bad_stakes_rejected(self) -> None:
        with self.assertRaises(tip.TrustInversionError):
            tip.calibrate_gate_strength(_signals(), base_strength=0.4, stakes="medium")  # type: ignore[arg-type]

    def test_bad_base_rejected(self) -> None:
        with self.assertRaises(tip.TrustInversionError):
            tip.calibrate_gate_strength(_signals(), base_strength=2.0)

    def test_disposition_and_reason_in_fixed_vocabulary(self) -> None:
        decision = tip.calibrate_gate_strength(_signals(), base_strength=0.4)
        self.assertIn(decision.disposition, tip.DISPOSITIONS)
        self.assertIn(decision.reason, tip.DECISION_REASONS)


class MainTests(unittest.TestCase):
    def test_main_returns_zero(self) -> None:
        self.assertEqual(tip.main(), 0)


if __name__ == "__main__":
    unittest.main()
