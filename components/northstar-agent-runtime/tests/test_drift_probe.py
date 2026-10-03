"""Post-release drift detection (ninetieth batch).

Covers ``drift_probe.py``:
- Window pairing is fail-closed (empty, duplicates, unpaired ids raise).
- Bootstrap CI is deterministic in the seed and brackets the effect.
- The paired permutation test is deterministic; a zero-variance window
  yields exactly p=1.0 (not 0.0, not a crash).
- ``detect_drift`` flags a simulated silent degradation, flags an
  improvement as improvement, and stays quiet on an unchanged window.
- The verdict requires the conjunction (p < alpha AND CI excludes zero
  AND |effect| >= min_effect).
"""
from __future__ import annotations

import unittest

import support  # noqa: F401

import drift_probe
from drift_probe import (
    DriftProbeError,
    DriftSample,
    bootstrap_ci,
    detect_drift,
    mean_difference,
    pair_windows,
    paired_differences,
    paired_permutation_test,
    samples_from_passed,
)


def _tasks(n: int = 40) -> list[str]:
    return [f"task-{i:03d}" for i in range(n)]


class TestPairing(unittest.TestCase):
    def test_happy_path_pairs_by_task_id(self) -> None:
        tasks = _tasks(4)
        base = samples_from_passed(tasks, tasks[:3], "2026-09")
        curr = samples_from_passed(tasks, tasks[:2], "2026-10")
        pairs = pair_windows(base, curr)
        self.assertEqual(len(pairs), 4)
        self.assertEqual(
            pairs[0], ("task-000", True, True)
        )
        self.assertEqual(pairs[2], ("task-002", True, False))

    def test_empty_window_raises(self) -> None:
        tasks = _tasks(4)
        curr = samples_from_passed(tasks, tasks, "2026-10")
        with self.assertRaises(DriftProbeError):
            pair_windows([], curr)
        with self.assertRaises(DriftProbeError):
            pair_windows(curr, [])

    def test_duplicate_task_ids_raise(self) -> None:
        dup = [
            DriftSample("t-1", True, "w1"),
            DriftSample("t-1", False, "w1"),
        ]
        other = [DriftSample("t-1", True, "w2")]
        with self.assertRaises(DriftProbeError):
            pair_windows(dup, other)

    def test_unpaired_task_ids_raise(self) -> None:
        base = [DriftSample("t-1", True, "w1"), DriftSample("t-2", True, "w1")]
        curr = [DriftSample("t-1", True, "w2"), DriftSample("t-3", True, "w2")]
        with self.assertRaises(DriftProbeError):
            pair_windows(base, curr)

    def test_non_bool_passed_raises(self) -> None:
        base = [DriftSample("t-1", 1, "w1")]  # type: ignore[arg-type]
        curr = [DriftSample("t-1", True, "w2")]
        with self.assertRaises(DriftProbeError):
            pair_windows(base, curr)

    def test_samples_from_passed_rejects_unknown_ids(self) -> None:
        with self.assertRaises(DriftProbeError):
            samples_from_passed(_tasks(4), ["task-999"], "w")


class TestStatistics(unittest.TestCase):
    def test_mean_difference_sign(self) -> None:
        pairs = [("t", True, False), ("u", True, True)]
        self.assertAlmostEqual(mean_difference(pairs), -0.5)

    def test_bootstrap_ci_is_deterministic_and_brackets_effect(self) -> None:
        tasks = _tasks(40)
        base = samples_from_passed(tasks, [t for t in tasks if int(t[-2:]) % 10 != 9], "w1")
        curr = samples_from_passed(
            tasks, [t for t in tasks if int(t[-2:]) % 10 not in (8, 9)], "w2"
        )
        pairs = pair_windows(base, curr)
        effect = mean_difference(pairs)
        lo, hi = bootstrap_ci(pairs, seed=7)
        lo2, hi2 = bootstrap_ci(pairs, seed=7)
        self.assertEqual((lo, hi), (lo2, hi2))
        self.assertLessEqual(lo, effect)
        self.assertLessEqual(effect, hi)
        # Degradation: the whole CI sits below zero.
        self.assertLess(hi, 0.0)

    def test_permutation_test_is_deterministic(self) -> None:
        tasks = _tasks(40)
        base = samples_from_passed(tasks, tasks[:36], "w1")
        curr = samples_from_passed(tasks, tasks[:28], "w2")
        pairs = pair_windows(base, curr)
        self.assertEqual(
            paired_permutation_test(pairs, seed=11),
            paired_permutation_test(pairs, seed=11),
        )

    def test_zero_variance_window_gives_p_one(self) -> None:
        tasks = _tasks(10)
        base = samples_from_passed(tasks, tasks, "w1")
        curr = samples_from_passed(tasks, tasks, "w2")
        pairs = pair_windows(base, curr)
        self.assertEqual(paired_permutation_test(pairs), 1.0)
        lo, hi = bootstrap_ci(pairs)
        self.assertEqual((lo, hi), (0.0, 0.0))

    def test_paired_differences_rejects_empty(self) -> None:
        with self.assertRaises(DriftProbeError):
            paired_differences([])


class TestDetectDrift(unittest.TestCase):
    def _windows(self, n: int = 40):
        tasks = _tasks(n)
        return tasks

    def test_silent_degradation_is_flagged(self) -> None:
        tasks = self._windows()
        base = samples_from_passed(
            tasks, [t for t in tasks if int(t[-2:]) % 10 != 9], "2026-09"
        )  # 36/40 pass
        curr = samples_from_passed(
            tasks, [t for t in tasks if int(t[-2:]) % 10 not in (6, 7, 8, 9)], "2026-10"
        )  # 24/40 pass: a silent 30-point downgrade
        verdict = detect_drift(base, curr)
        self.assertTrue(verdict.drift_detected)
        self.assertEqual(verdict.direction, "degradation")
        self.assertLess(verdict.p_value, 0.05)
        self.assertLess(verdict.ci_hi, 0.0)
        self.assertEqual(verdict.n_pairs, 40)
        self.assertAlmostEqual(verdict.effect, -0.30)

    def test_improvement_is_flagged_as_improvement(self) -> None:
        tasks = self._windows()
        base = samples_from_passed(tasks, tasks[:20], "w1")
        curr = samples_from_passed(tasks, tasks[:32], "w2")
        verdict = detect_drift(base, curr)
        self.assertTrue(verdict.drift_detected)
        self.assertEqual(verdict.direction, "improvement")
        self.assertGreater(verdict.effect, 0.0)

    def test_unchanged_window_stays_quiet(self) -> None:
        tasks = self._windows()
        base = samples_from_passed(tasks, tasks[:36], "w1")
        curr = samples_from_passed(tasks, tasks[:36], "w2")
        verdict = detect_drift(base, curr)
        self.assertFalse(verdict.drift_detected)
        self.assertEqual(verdict.direction, "none")
        self.assertEqual(verdict.p_value, 1.0)

    def test_tiny_wobble_below_min_effect_stays_quiet(self) -> None:
        tasks = self._windows(200)
        base = samples_from_passed(tasks, tasks[:180], "w1")
        curr = samples_from_passed(tasks, tasks[:179], "w2")
        verdict = detect_drift(base, curr, min_effect=0.05)
        self.assertFalse(verdict.drift_detected)
        self.assertEqual(verdict.direction, "none")

    def test_verdict_is_deterministic(self) -> None:
        tasks = self._windows()
        base = samples_from_passed(tasks, tasks[:36], "w1")
        curr = samples_from_passed(tasks, tasks[:28], "w2")
        first = detect_drift(base, curr).as_dict()
        second = detect_drift(base, curr).as_dict()
        self.assertEqual(first, second)

    def test_verdict_dict_carries_schema(self) -> None:
        tasks = self._windows(8)
        base = samples_from_passed(tasks, tasks, "w1")
        curr = samples_from_passed(tasks, tasks, "w2")
        payload = detect_drift(base, curr).as_dict()
        self.assertEqual(payload["schema"], drift_probe.DRIFT_PROBE_SCHEMA_VERSION)
        self.assertIn("ci", payload)

    def test_bad_alpha_raises(self) -> None:
        tasks = self._windows(8)
        base = samples_from_passed(tasks, tasks, "w1")
        curr = samples_from_passed(tasks, tasks, "w2")
        with self.assertRaises(DriftProbeError):
            detect_drift(base, curr, alpha=0.0)
        with self.assertRaises(DriftProbeError):
            detect_drift(base, curr, min_effect=-0.1)


if __name__ == "__main__":
    unittest.main()
