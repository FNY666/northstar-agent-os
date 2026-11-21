#!/usr/bin/env python3
"""Extend the seccomp capability tests to cover the path requirement.

A case that cannot make its proof must also stop demanding the proof's
artifact: leaving "filter_live.txt" required on a host that cannot create
it turns "no capability" back into a failure, which is the whole thing
these cases are trying to stop doing.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import support  # noqa: F401  (bootstraps sys.path)
import governance_bench  # noqa: E402


class SeccompPathRequirementTests(unittest.TestCase):
    def _build(self, case_id, loadable):
        original = governance_bench.seccomp_filter_loadable
        governance_bench.seccomp_filter_loadable = lambda: loadable
        self.addCleanup(
            setattr, governance_bench, "seccomp_filter_loadable", original
        )
        for case in governance_bench.CASES:
            if case.id == case_id:
                harness = governance_bench.BenchHarness()
                self.addCleanup(harness.close)
                return case.build(harness)
        raise AssertionError(f"case not found: {case_id}")

    def test_a_host_without_seccomp_does_not_require_the_proof_file(self):
        expectation = self._build("denial.seccomp_filter_live_on_process", False)
        self.assertEqual(expectation.require_paths, ())

    def test_a_host_with_seccomp_still_requires_the_proof_file(self):
        expectation = self._build("denial.seccomp_filter_live_on_process", True)
        self.assertIn("filter_live.txt", expectation.require_paths)

    def test_the_tighten_only_case_drops_its_proof_file_too(self):
        expectation = self._build("denial.seccomp_payload_cannot_loosen", False)
        self.assertEqual(expectation.require_paths, ())

    def test_the_tighten_only_case_still_requires_its_file_when_supported(self):
        expectation = self._build("denial.seccomp_payload_cannot_loosen", True)
        self.assertIn("tightened.txt", expectation.require_paths)

    def test_the_notes_say_the_proof_was_not_made(self):
        expectation = self._build("denial.seccomp_filter_live_on_process", False)
        self.assertIn("not made", expectation.notes.lower())


if __name__ == "__main__":
    unittest.main()
