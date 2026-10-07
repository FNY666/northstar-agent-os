"""Tests for edge_gate_ml.py: the continuous-score edge gate variant."""

from __future__ import annotations

import importlib.util
import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from edge_gate_ml import (
    ALLOW_BELOW,
    DENY_ABOVE,
    ML_GATE_VERSION,
    WEIGHT_PIN,
    MLEdgeGate,
    MLGateDecision,
    RiskFeatures,
    edge_gate_ml_event,
    extract_features,
    score_risk,
    verdict_for_score,
)


def _load_rule_gate():
    """Load github/main's rule-based edge_gate: installed copy first,
    /tmp snapshot fallback (branch-flip-proof)."""
    try:
        import edge_gate

        return edge_gate
    except ImportError:
        pass
    path = "/tmp/edge_gate_main.py"
    if not os.path.exists(path):
        raise unittest.SkipTest("rule-based edge_gate unavailable for comparison")
    spec = importlib.util.spec_from_file_location("edge_gate_rule", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestVersionPin(unittest.TestCase):
    def test_pins_present(self):
        self.assertEqual(ML_GATE_VERSION, "edge-gate-ml.v1")
        self.assertEqual(WEIGHT_PIN, "northstar.edge-gate-ml.weights.v1")
        self.assertLess(ALLOW_BELOW, DENY_ABOVE)


class TestFeatureExtraction(unittest.TestCase):
    def test_reversible_action(self):
        f = extract_features({"action_type": "files.read"})
        self.assertEqual(f.verb, "read")
        self.assertEqual(f.target, "files")
        self.assertTrue(f.has_reversible_token)
        self.assertFalse(f.has_physical_token)
        self.assertFalse(f.is_unknown)

    def test_physical_action(self):
        f = extract_features({"action_type": "robot.move"})
        self.assertEqual(f.verb, "move")
        self.assertEqual(f.target, "robot")
        self.assertTrue(f.has_physical_token)

    def test_malformed_is_unknown(self):
        for bad in (None, 42, [], "x", {"action_type": 5}, {"action_type": ""}):
            f = extract_features(bad)
            self.assertTrue(f.is_unknown, f"not unknown: {bad!r}")

    def test_history_clamped(self):
        f = extract_features({"action_type": "db.delete"}, past_deny_rate=99.0, past_human_count=100)
        self.assertEqual(f.past_deny_rate, 1.0)
        self.assertEqual(f.past_human_count, 5)
        f = extract_features({"action_type": "db.delete"}, past_deny_rate=-1.0, past_human_count=-3)
        self.assertEqual(f.past_deny_rate, 0.0)
        self.assertEqual(f.past_human_count, 0)


class TestScoring(unittest.TestCase):
    def test_bounds(self):
        corpus = [
            {"action_type": "files.read"},
            {"action_type": "db.delete"},
            {"action_type": "robot.move"},
            {"action_type": "a.b.c.d.e.f"},
            {"action_type": "newsletter.send"},
        ]
        for action in corpus:
            s = score_risk(extract_features(action))
            self.assertGreaterEqual(s, 0.0)
            self.assertLessEqual(s, 1.0)

    def test_reversible_scores_low(self):
        self.assertLess(score_risk(extract_features({"action_type": "files.read"})), 0.3)

    def test_physical_scores_high(self):
        self.assertGreater(score_risk(extract_features({"action_type": "robot.move"})), 0.7)

    def test_malformed_scores_one(self):
        self.assertEqual(score_risk(extract_features(None)), 1.0)
        self.assertEqual(score_risk("not-a-features"), 1.0)

    def test_history_raises_score(self):
        base = score_risk(extract_features({"action_type": "files.read"}))
        bad_hist = score_risk(
            extract_features(
                {"action_type": "files.read"}, past_deny_rate=1.0, past_human_count=5
            )
        )
        self.assertGreater(bad_hist, base)


class TestVerdictMapping(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(verdict_for_score(0.29), "allow")
        self.assertEqual(verdict_for_score(0.3), "require_human")
        self.assertEqual(verdict_for_score(0.7), "require_human")
        self.assertEqual(verdict_for_score(0.71), "deny")
        self.assertEqual(verdict_for_score(float("nan")), "deny")
        self.assertEqual(verdict_for_score("garbage"), "deny")
        self.assertEqual(verdict_for_score(None), "deny")


class TestMLGate(unittest.TestCase):
    def test_check_verdicts(self):
        gate = MLEdgeGate(irreversible_allowlist=("newsletter.send",))
        self.assertEqual(gate.check({"action_type": "files.read"}), "allow")
        self.assertEqual(gate.check({"action_type": "db.delete"}), "require_human")
        self.assertEqual(gate.check({"action_type": ""}), "deny")
        self.assertEqual(gate.check(None), "deny")

    def test_never_raises(self):
        gate = MLEdgeGate()
        for bad in (None, 42, [], "x", {"a": 1}, {"action_type": object()}):
            self.assertIn(gate.check(bad), ("allow", "deny", "require_human"))

    def test_frozen_decision(self):
        gate = MLEdgeGate()
        d = gate.check_detailed({"action_type": "files.read"}, seq=7)
        self.assertIsInstance(d, MLGateDecision)
        self.assertEqual(d.seq, 7)
        with self.assertRaises(Exception):
            d.verdict = "deny"  # frozen

    def test_bad_seq_normalized(self):
        gate = MLEdgeGate()
        d = gate.check_detailed({"action_type": "files.read"}, seq=-1)
        self.assertEqual(d.seq, 0)


class TestRuleComparison(unittest.TestCase):
    """Head-to-head: rule-based edge_gate vs score-based MLEdgeGate.

    Documents where the two methods agree (the optimal point: keep the
    rule) and where they diverge (the optimal point: know which bias
    you are buying).
    """

    def test_agree_on_clear_cut(self):
        rule = _load_rule_gate()
        rgate = rule.EdgeGate(irreversible_allowlist=("newsletter.send",))
        mgate = MLEdgeGate(irreversible_allowlist=("newsletter.send",))
        agree = {
            "files.read": "allow",
            "db.delete": "require_human",
            "newsletter.send": "allow",
        }
        for action_type, expected in agree.items():
            action = {"action_type": action_type}
            self.assertEqual(rgate.check(action), expected, action_type)
            self.assertEqual(mgate.check(action), expected, action_type)

    def test_both_deny_malformed(self):
        rule = _load_rule_gate()
        rgate = rule.EdgeGate()
        mgate = MLEdgeGate()
        for bad in (None, 42, {"action_type": ""}):
            self.assertEqual(rgate.check(bad), "deny")
            self.assertEqual(mgate.check(bad), "deny")

    def test_diverge_on_named_physical(self):
        # Rules preserve a human decision path for named physical
        # actions; the ML table (physical weight 0.75 > 0.7) denies
        # outright. A 0.10 weight change flips this - the silent
        # calibration risk scores carry and rules do not.
        rule = _load_rule_gate()
        rgate = rule.EdgeGate()
        mgate = MLEdgeGate()
        action = {"action_type": "robot.move"}
        self.assertEqual(rgate.check(action), "require_human")
        self.assertEqual(mgate.check(action), "deny")

    def test_diverge_on_tainted_allowlist(self):
        # An allowlisted irreversible with a bad history: rules still
        # allow (the allowlist is unconditional); the score climbs back
        # into "require_human". Rules have no memory; scores do.
        rule = _load_rule_gate()
        rgate = rule.EdgeGate(irreversible_allowlist=("newsletter.send",))
        mgate = MLEdgeGate(irreversible_allowlist=("newsletter.send",))
        action = {"action_type": "newsletter.send"}
        history = {"deny_rate": 1.0, "human_count": 5}
        self.assertEqual(rgate.check(action), "allow")
        self.assertEqual(mgate.check(action, history=history), "require_human")

    def test_audit_event_shape(self):
        gate = MLEdgeGate()
        d = gate.check_detailed({"action_type": "db.delete"}, seq=3)
        ev = edge_gate_ml_event(d)
        self.assertEqual(ev["type"], "edge-gate-ml.decision")
        self.assertEqual(ev["verdict"], "require_human")
        self.assertEqual(ev["weight_pin"], WEIGHT_PIN)
        self.assertIn("decision_digest", ev)


if __name__ == "__main__":
    unittest.main()
