"""Tests for the deny-monotonicity check.

The check pins the gate's deny set and fails the bench whenever a gate
change silently drops a denial. These tests cover the corpus shape, the
real-gate deny set against the pinned baseline, and the monotonicity
math (including the fail-closed missing-baseline path).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import deny_monotonicity as dm


class DenyCorpusShapeTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(dm.DENY_MONOTONICITY_VERSION, "deny-monotonicity.v1")

    def test_corpus_covers_distinct_deny_paths(self):
        self.assertGreaterEqual(len(dm.DENY_CORPUS), 4)
        for probe in dm.DENY_CORPUS:
            for field in ("probe", "tool", "kind", "payload", "config", "why"):
                self.assertIn(field, probe, f"canary needs {field!r}")
        ids = [p["probe"] for p in dm.DENY_CORPUS]
        self.assertEqual(len(ids), len(set(ids)), "canary ids must be unique")

    def test_baseline_file_exists_and_parses(self):
        path = dm.baseline_path()
        self.assertTrue(path.exists(), "pinned baseline JSON must ship with the repo")
        raw = json.loads(path.read_text())
        self.assertEqual(raw["version"], dm.DENY_MONOTONICITY_VERSION)
        self.assertTrue(raw["deny_set"])


class ComputeDenySetTests(unittest.TestCase):
    def test_real_gate_denies_every_canary(self):
        deny_set = dm.compute_deny_set(dm.DENY_CORPUS, dm.build_gate_fn())
        canaries = {p["probe"] for p in dm.DENY_CORPUS}
        denied_canaries = {p for p, _ in deny_set}
        self.assertEqual(denied_canaries, canaries)

    def test_real_gate_matches_pinned_baseline(self):
        # The anchor test: the current gate must reproduce the pinned
        # baseline exactly. Any drift here means gate behavior changed
        # and the baseline needs a reviewed regeneration.
        deny_set = dm.compute_deny_set(dm.DENY_CORPUS, dm.build_gate_fn())
        pinned = dm.load_baseline()
        self.assertEqual(deny_set, pinned)

    def test_allow_never_lands_in_deny_set(self):
        def allow_all(probe):
            class D:
                allowed = True
                deny_code = ""

            return D()

        self.assertEqual(dm.compute_deny_set(dm.DENY_CORPUS, allow_all), set())

    def test_deny_code_recorded_per_canary(self):
        deny_set = dm.compute_deny_set(dm.DENY_CORPUS, dm.build_gate_fn())
        codes = {c for _, c in deny_set}
        # Every canary must carry a machine-readable code, never blank.
        self.assertNotIn("", codes)
        self.assertNotIn("denial.unspecified", codes)


class MonotonicityMathTests(unittest.TestCase):
    def test_monotonic_pass_superset(self):
        old = {("a", "denial.x"), ("b", "denial.y")}
        new = {("a", "denial.x"), ("b", "denial.y"), ("c", "denial.z")}
        ok, loosened = dm.check_monotonicity(old, new)
        self.assertTrue(ok)
        self.assertEqual(loosened, [])

    def test_loosening_detected(self):
        old = {("a", "denial.x"), ("b", "denial.y")}
        new = {("a", "denial.x")}
        ok, loosened = dm.check_monotonicity(old, new)
        self.assertFalse(ok)
        self.assertEqual(loosened, [("b", "denial.y")])

    def test_deny_code_change_is_a_loosening(self):
        # Same probe still denies, but under a different code: the old
        # (probe, code) pair is gone, which is a semantic change the
        # bench must flag rather than silently accept.
        old = {("a", "denial.x")}
        new = {("a", "denial.x2")}
        ok, loosened = dm.check_monotonicity(old, new)
        self.assertFalse(ok)
        self.assertEqual(loosened, [("a", "denial.x")])

    def test_empty_baseline_is_always_monotonic(self):
        ok, loosened = dm.check_monotonicity(set(), {("a", "denial.x")})
        self.assertTrue(ok)
        self.assertEqual(loosened, [])

    def test_empty_new_set_loses_everything(self):
        old = {("a", "denial.x"), ("b", "denial.y")}
        ok, loosened = dm.check_monotonicity(old, set())
        self.assertFalse(ok)
        self.assertEqual(loosened, [("a", "denial.x"), ("b", "denial.y")])

    def test_loosened_is_sorted_deterministic(self):
        old = {("z", "denial.1"), ("a", "denial.2"), ("m", "denial.3")}
        _, loosened = dm.check_monotonicity(old, set())
        self.assertEqual(loosened, sorted(loosened))


class BenchCheckTests(unittest.TestCase):
    def test_check_ok_against_real_baseline(self):
        ok, message = dm.deny_monotonicity_check()
        self.assertTrue(ok, message)
        self.assertIn("0 lost", message)

    def test_check_reports_loosened_denials(self):
        # Baseline with an extra pair the current gate never produces.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            current = dm.compute_deny_set(dm.DENY_CORPUS, dm.build_gate_fn())
            extra = set(current) | {("phantom-canary", "denial.ghost")}
            dm.save_baseline(extra, path)
            ok, message = dm.deny_monotonicity_check(baseline=path)
            self.assertFalse(ok)
            self.assertIn("phantom-canary", message)
            self.assertIn("denial.ghost", message)

    def test_missing_baseline_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, message = dm.deny_monotonicity_check(
                baseline=Path(tmp) / "nope.json"
            )
            self.assertFalse(ok)
            self.assertIn("missing", message)

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            deny_set = {("a", "denial.x"), ("b", "denial.y")}
            dm.save_baseline(deny_set, path)
            self.assertEqual(dm.load_baseline(path), deny_set)

    def test_regenerate_baseline_reproduces_current_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            dm.regenerate_baseline(path=path)
            current = dm.compute_deny_set(dm.DENY_CORPUS, dm.build_gate_fn())
            self.assertEqual(dm.load_baseline(path), current)


if __name__ == "__main__":
    unittest.main()
