"""Tests for G (refusal quality) and H (substitution equivalence) lines."""

from __future__ import annotations

import unittest

import support  # noqa: F401 — sys.path bootstrap

from governance_bench import (
    CASES,
    REFUSAL_CHAINS,
    run_refusal_quality,
    run_substitution_equivalence,
)


class RefusalQualityTests(unittest.TestCase):
    def test_is_deterministic(self):
        self.assertEqual(run_refusal_quality(), run_refusal_quality())

    def test_perfect_scores(self):
        m = run_refusal_quality()
        self.assertEqual(m["n_chains"], len(REFUSAL_CHAINS))
        self.assertGreater(m["n_chains"], 0)
        # The gate denies at the first attack step of every chain.
        self.assertEqual(m["timeliness"], 1.0)
        self.assertEqual(m["restraint"], 1.0)
        self.assertEqual(m["refuse_correctness"], 1.0)

    def test_case_registered(self):
        case = next(c for c in CASES if c.id == "metrics.refusal_quality")
        self.assertEqual(case.track, "metrics")


class SubstitutionEquivalenceTests(unittest.TestCase):
    def test_is_deterministic(self):
        self.assertEqual(
            run_substitution_equivalence(), run_substitution_equivalence()
        )

    def test_gap_measured(self):
        m = run_substitution_equivalence()
        # All native denials are Tier-3 (policy/callback); exempting the
        # tool flips them — the gap documents exemption risk.
        self.assertGreater(m["n_tested"], 0)
        self.assertEqual(m["n_flipped"], m["n_tested"])
        self.assertEqual(m["substitution_gap_rate"], 1.0)

    def test_case_registered(self):
        case = next(
            c for c in CASES if c.id == "metrics.substitution_equivalence"
        )
        self.assertEqual(case.track, "metrics")


if __name__ == "__main__":
    unittest.main()
