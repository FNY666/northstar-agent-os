"""Tests for scoring a measurement only on the tasks that can carry one.

A task whose empty patch also passes cannot tell a fix from a no-op, so
whatever the model scored there is noise. These tests make sure such a task
is excluded from the trusted score and named rather than dropped.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from swe_bench_trust import check_sample, score  # noqa: E402


def _measurement(tasks: list[tuple[str, str]], sha: str = "s1") -> dict:
    return {
        "sample_sha256": sha,
        "tasks": [{"instance_id": i, "outcome": o} for i, o in tasks],
    }


def _integrity(verdicts: dict[str, str], sha: str = "s1") -> dict:
    return {
        "sample_sha256": sha,
        "instances": [{"instance_id": i, "verdict": v} for i, v in verdicts.items()],
    }


class TrustScoreTests(unittest.TestCase):
    def test_the_trusted_score_covers_only_the_trustworthy_tasks(self):
        measurement = _measurement(
            [
                ("a", "RESOLVED_FULL"),
                ("b", "RESOLVED_FULL"),
                ("c", "RESOLVED_NO"),
            ]
        )
        integrity = _integrity(
            {"a": "trustworthy", "b": "trustworthy", "c": "trustworthy"}
        )
        result = score(measurement, integrity)
        # Only a fully resolved task counts as resolved, but a task the
        # grader judged and the model missed is still in the denominator.
        self.assertEqual(result.trusted_tasks, 3)
        self.assertAlmostEqual(result.trusted, 2 / 3)

    def test_a_task_whose_empty_patch_also_passed_is_excluded_and_named(self):
        measurement = _measurement(
            [("a", "RESOLVED_FULL"), ("b", "RESOLVED_FULL")]
        )
        integrity = _integrity({"a": "trustworthy", "b": "empty_patch_accepted"})
        result = score(measurement, integrity)
        self.assertEqual(result.trusted_tasks, 1)
        self.assertAlmostEqual(result.trusted, 1.0)
        self.assertEqual(result.tainted, ["b"])

    def test_a_task_whose_run_broke_is_not_counted_as_a_failure(self):
        measurement = _measurement(
            [("a", "RESOLVED_FULL"), ("b", "evaluation_infrastructure_failure")]
        )
        integrity = _integrity({"a": "trustworthy", "b": "inconclusive"})
        result = score(measurement, integrity)
        self.assertEqual(result.overall_unjudged, 1)
        self.assertAlmostEqual(result.overall, 1.0)

    def test_a_task_the_model_missed_is_in_the_denominator(self):
        # It is a real verdict: the model was wrong, and the rate has to
        # show it. Only a task that was never judged is left out.
        measurement = _measurement(
            [("a", "RESOLVED_FULL"), ("b", "RESOLVED_NO")]
        )
        integrity = _integrity({"a": "trustworthy", "b": "trustworthy"})
        result = score(measurement, integrity)
        self.assertEqual(result.overall_pool, 2)
        self.assertAlmostEqual(result.overall, 0.5)

    def test_an_unchecked_task_is_not_treated_as_a_broken_one(self):
        # A task the integrity check never reached says nothing about the
        # sample; it must not be named as tainted.
        measurement = _measurement([("a", "RESOLVED_FULL")])
        integrity = _integrity({})
        result = score(measurement, integrity)
        self.assertEqual(result.tainted, [])

    def test_the_overall_score_covers_every_judged_task(self):
        measurement = _measurement(
            [
                ("a", "RESOLVED_FULL"),
                ("b", "RESOLVED_FULL"),
                ("c", "RESOLVED_NO"),
                ("d", "no_patch_delivered"),
            ]
        )
        integrity = _integrity({"a": "trustworthy", "b": "empty_patch_accepted"})
        result = score(measurement, integrity)
        self.assertAlmostEqual(result.overall, 2 / 3)
        self.assertEqual(result.overall_pool, 3)
        self.assertEqual(result.overall_unjudged, 1)

    def test_a_partial_resolution_is_judged_but_not_resolved(self):
        # The same rule the measurement record uses: a task counts as
        # resolved only when it is fully resolved.
        measurement = _measurement(
            [("a", "RESOLVED_FULL"), ("b", "RESOLVED_PARTIAL")]
        )
        integrity = _integrity({"a": "trustworthy", "b": "trustworthy"})
        result = score(measurement, integrity)
        self.assertEqual(result.overall_unjudged, 0)
        self.assertEqual(result.overall_pool, 2)
        # The partial resolution is a verdict, so it is in the denominator;
        # it is not a resolution, so it is not in the numerator.
        self.assertEqual(result.trusted_tasks, 2)
        self.assertAlmostEqual(result.trusted, 0.5)

    def test_two_different_samples_are_reported(self):
        note = check_sample(_measurement([], sha="a"), _integrity({}, sha="b"))
        self.assertIn("different samples", note)

    def test_the_same_sample_is_not_reported(self):
        self.assertEqual(check_sample(_measurement([], sha="a"), _integrity({}, sha="a")), "")

    def test_the_breakdown_says_where_each_outcome_went(self):
        measurement = _measurement([("a", "RESOLVED_FULL"), ("b", "RESOLVED_NO")])
        integrity = _integrity({"a": "trustworthy", "b": "empty_patch_accepted"})
        result = score(measurement, integrity)
        self.assertEqual(result.breakdown["trustworthy"]["RESOLVED_FULL"], 1)
        self.assertEqual(result.breakdown["empty_patch_accepted"]["RESOLVED_NO"], 1)


if __name__ == "__main__":
    unittest.main()
