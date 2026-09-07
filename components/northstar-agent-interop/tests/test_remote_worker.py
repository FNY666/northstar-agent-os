"""The P3-3 readiness scorecard must stay honest.

These tests pin the *scorecard's quality*, not the components:

- the evaluator runs and covers every area with real checks;
- the kernel-area checks that are True today stay True (a renamed symbol
  would otherwise silently widen a gap that the code does not have);
- every expected-gap probe ("MISSING: ...") is False today — the moment one
  of those work items lands, its probe turns True and this test forces the
  maintainer to move it out of the gap list on purpose.
"""
import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

import remote_worker as rw  # noqa: E402


class ScorecardCoverageTests(unittest.TestCase):
    def test_every_area_has_checks(self):
        areas_with_checks = {area for area, _, _ in rw.CHECKS}
        self.assertEqual(areas_with_checks, {area for area, _ in rw.AREAS})

    def test_score_and_total_are_consistent(self):
        result = rw.score()
        met = sum(value[0] for value in result.values())
        total = sum(value[1] for value in result.values())
        self.assertEqual(rw.total_score(), round(100 * met / total))
        for area, (area_met, area_total, _) in result.items():
            self.assertLessEqual(area_met, area_total)
            self.assertGreater(area_total, 0)

    def test_kernel_areas_are_fully_present(self):
        # The P3-3 claim is that the governance/contract layers are ready and
        # the gaps are ops-only. A regression here is a real signal, not noise.
        result = rw.score()
        for area in ("contracts", "host", "durable-run", "interop", "audit"):
            with self.subTest(area=area):
                met, total, _ = result[area]
                self.assertEqual(
                    (met, total), (total, total),
                    f"{area} is no longer fully present; a renamed symbol may have "
                    "silently widened a gap the code does not have",
                )

    def test_every_expected_gap_is_still_a_gap(self):
        for area, check, explanation in rw.CHECKS:
            if explanation.startswith("MISSING"):
                with self.subTest(explanation=explanation):
                    self.assertFalse(
                        check(),
                        f"{explanation} now passes - move it out of the gap list on purpose",
                    )


class CliSmokeTests(unittest.TestCase):
    def test_cli_score_exits_zero_and_prints_a_number(self):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = rw._run(["--score"])
        self.assertEqual(code, 0)
        self.assertRegex(out.getvalue(), r"remote-worker readiness: \d+/100")


if __name__ == "__main__":
    unittest.main()
