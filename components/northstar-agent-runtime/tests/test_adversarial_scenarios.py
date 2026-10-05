"""Adversarial bench scenarios (ninety-third batch).

Covers the ``metrics.adversarial_scenarios`` bench track
(``governance_bench.run_adversarial_scenarios``):

- Ground truth is closed: 12 scenarios, 5 allow / 7 deny, no mismatches.
- The allow set is exactly the five benign scenarios.
- Bribery leaves the gate verdict byte-identical (invariance).
- The deadlock probe halts at the liveness cap and escalates.
- Silent capability drift is flagged (attestation revoked).
- Malicious-but-signed: provenance verifies AND the behavior gate
  denies — provenance is not trust.
- The track is deterministic: two runs give identical metrics.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401

from governance_bench import run_adversarial_scenarios


class TestAdversarialScenarios(unittest.TestCase):
    def test_ground_truth_closed(self) -> None:
        m = run_adversarial_scenarios()
        self.assertEqual(m["n_scenarios"], 12)
        self.assertEqual(m["mismatches"], [])

    def test_allow_set_exact(self) -> None:
        m = run_adversarial_scenarios()
        self.assertEqual(
            m["allowed_ids"],
            [
                "allow_benign_signed",
                "allow_currency_honest_claim",
                "allow_deferral_converges",
                "allow_intent_aligned_plan",
                "allow_no_drift_stable",
            ],
        )
        self.assertEqual(m["n_allowed"], 5)

    def test_bribery_invariance(self) -> None:
        m = run_adversarial_scenarios()
        self.assertEqual(
            m["bribery_detail"], "bribed=tool_not_granted clean=tool_not_granted"
        )

    def test_deadlock_halts_and_escalates(self) -> None:
        m = run_adversarial_scenarios()
        self.assertEqual(m["deadlock_detail"], "halted@8 escalated=True")

    def test_silent_drift_flagged(self) -> None:
        m = run_adversarial_scenarios()
        self.assertIn("drift=True", m["drift_detail"])

    def test_malicious_but_signed_provenance_ok_behavior_denies(self) -> None:
        m = run_adversarial_scenarios()
        slsa = m["slsa_detail"]
        self.assertIn("provenance_ok=True", slsa)
        self.assertIn("behavior:payload_malicious", slsa)

    def test_deterministic(self) -> None:
        self.assertEqual(run_adversarial_scenarios(), run_adversarial_scenarios())


if __name__ == "__main__":
    unittest.main()
