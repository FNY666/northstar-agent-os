"""Red tests for the seccomp benchmark cases on a host without seccomp.

Two benchmark cases prove that the seccomp denylist is really loaded: the
child must observe "Seccomp: 2" and create a proof file. On a kernel without
CONFIG_SECCOMP_FILTER that never happens, and the case reports a failed
promise about the product.

The capdrop case already handles this: when the host cannot enforce the
capability, its engine check does not demand the live proof, and the report
says "supported=false" so the reader knows the proof was not made. The
seccomp cases must do the same rather than claim a broken product.
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


class SeccompCaseCapabilityTests(unittest.TestCase):
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

    def test_a_host_without_seccomp_does_not_fail_the_live_filter_case(self):
        expectation = self._build("denial.seccomp_filter_live_on_process", False)
        self.assertTrue(
            expectation.engine_ok,
            "a host that cannot load a BPF filter cannot be told the product is broken",
        )

    def test_the_case_reports_that_the_proof_was_not_made(self):
        expectation = self._build("denial.seccomp_filter_live_on_process", False)
        metrics = expectation.metrics or {}
        self.assertFalse(metrics.get("supported", True))

    def test_a_host_with_seccomp_still_has_to_prove_it(self):
        expectation = self._build("denial.seccomp_filter_live_on_process", True)
        metrics = expectation.metrics or {}
        self.assertTrue(metrics.get("supported", False))

    def test_the_tighten_only_case_also_survives_a_host_without_seccomp(self):
        expectation = self._build("denial.seccomp_payload_cannot_loosen", False)
        self.assertTrue(
            expectation.engine_ok,
            "a host that cannot load a BPF filter cannot be told the product is broken",
        )


if __name__ == "__main__":
    unittest.main()
