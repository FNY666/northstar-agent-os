"""The baseline drift check must be WIRED INTO CI, not merely documented.

The rule pinned here:

> **CI runs the baseline check**, so "the failure set is identical to
> the baseline" is machine-checked rather than asserted in prose.

WHY THIS IS A SEPARATE RULE
----------------------------
The baseline drifted twice in one day -- 27 items, then 26, then 30 --
and four slices' reports were wrong about it, because nothing checked.
``scripts/b173-baseline-check.sh`` existed the whole time; it simply was
never run by anything.

Three things had to be true before it could be wired in, and each was a
blocker measured on its own:

1. **A checkout-local baseline.**  The baseline file lived at
   ``/home/muse-newapi/``, which a CI runner does not have.  A copy with
   provenance now lives at ``docs/baseline/current.failures.txt``.
2. **The runner CI uses.**  The check ran the suite with ``unittest``
   while CI runs ``pytest``.  unittest's discovery finds only test
   METHODS inside TestCase classes, so the check watched 23,171 tests
   while CI watched 33,295 -- it never saw the suite's 9,815 standalone
   module-level ``test_*`` functions, in 812 files.  The runner is now
   selectable and defaults to pytest.
3. **The path.**  The runtime job's ``working-directory`` is the
   component, so the step must reach the repository's ``scripts/``.

These tests read the REAL workflow and the REAL script.  They do not
run the suite: the check itself does that, and CI is about to run it.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"
SCRIPT = REPO_ROOT / "scripts" / "b173-baseline-check.sh"
LOCAL_BASELINE = REPO_ROOT / "docs" / "baseline" / "current.failures.txt"


class BaselineCheckWiringTests(unittest.TestCase):
    """CI must actually run the check."""

    def setUp(self):
        if not WORKFLOW.exists():
            self.skipTest(f"workflow missing: {WORKFLOW}")
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_ci_runs_the_baseline_check(self):
        """The whole point: the check must be run by something."""
        self.assertIn(
            "b173-baseline-check.sh", self.text,
            "no CI step runs the baseline check, so nothing machine-checks "
            "the baseline",
        )

    def test_the_step_reaches_the_script_from_the_components_working_directory(self):
        """The runtime job runs inside the component, not the repository root.

        A step written as ``bash scripts/b173-baseline-check.sh`` would
        fail there with "No such file or directory" -- which CI reports
        as a failure of the STEP, so the check would look wired while
        never having run.
        """
        self.assertIn(
            "bash ../../scripts/b173-baseline-check.sh", self.text,
            "the baseline check step does not resolve the script from the "
            "runtime component's working-directory",
        )

    def test_the_check_step_sits_in_the_runtime_job(self):
        """It must be in the job that runs the runtime suite.

        The runtime job is the one whose ``working-directory`` is
        ``components/northstar-agent-runtime`` and whose unit-test step
        runs ``pytest -q tests``.  A step in any other job would be
        comparing a failure set the runtime job never produced.
        """
        agent_runtime = self.text.find("agent-runtime:")
        self.assertNotEqual(agent_runtime, -1, "no agent-runtime job")
        documentation = self.text.find("documentation:")
        self.assertNotEqual(documentation, -1, "no documentation job")
        at = self.text.find("b173-baseline-check.sh")
        self.assertNotEqual(at, -1)
        self.assertGreater(
            at, agent_runtime,
            "the baseline check must run in the runtime job",
        )
        self.assertLess(
            at, documentation,
            "the baseline check must run before the documentation job",
        )

    def test_the_step_does_not_swallow_the_verdict(self):
        """A non-zero exit must FAIL the step, not be ignored.

        The check's exit codes are 0 = match, 1 = drift, 2 = could not
        measure.  If the step ignored the exit code, a drift would read
        as a pass -- the exact failure the check exists to prevent.
        """
        at = self.text.find("b173-baseline-check.sh")
        self.assertNotEqual(at, -1)
        # The step's `run:` line must not swallow the exit status.
        step = self.text[max(0, at - 800):at + 400]
        self.assertNotIn(
            "|| true", step,
            "the baseline check step swallows its exit code, so a drift "
            "would read as a pass",
        )
        self.assertNotIn(
            "continue-on-error", step,
            "the baseline check step is marked continue-on-error, so a "
            "drift would read as a pass",
        )


class BaselineCheckPrerequisitesTests(unittest.TestCase):
    """The three blockers that kept the check out of CI."""

    def test_a_checkout_local_baseline_exists(self):
        """A CI runner has no /home/muse-newapi."""
        self.assertTrue(
            LOCAL_BASELINE.exists(),
            f"missing checkout-local baseline: {LOCAL_BASELINE}",
        )

    def test_the_script_prefers_the_coordinators_file_when_present(self):
        """The in-repo copy must not become the authority.

        Re-taking a baseline is the coordinator's decision
        (docs/design/r6-baseline-unify.md section 5.1).
        """
        if not SCRIPT.exists():
            self.skipTest(f"baseline check script missing: {SCRIPT}")
        text = SCRIPT.read_text(encoding="utf-8")
        authority = "/home/muse-newapi/b173-baseline-failures-2026-11-14.txt"
        self.assertIn(authority, text)
        self.assertLess(
            text.index(authority),
            text.index("docs/baseline/current.failures.txt"),
            "the checkout-local baseline must be a FALLBACK, not the "
            "authority",
        )

    def test_the_default_runner_is_the_one_ci_uses(self):
        """pytest, not unittest.

        unittest's discovery collects only test METHODS inside TestCase
        classes.  The runtime suite has 9,815 standalone module-level
        ``test_*`` functions in 812 files that unittest never sees, so a
        unittest-based check watches 23,171 tests while CI watches
        33,295.
        """
        if not SCRIPT.exists():
            self.skipTest(f"baseline check script missing: {SCRIPT}")
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('RUNNER="${B173_BASELINE_RUNNER:-pytest}"', text)

    def test_the_check_can_refuse_to_measure(self):
        """Exit 2 must be distinct from MATCH (0) and DRIFT (1).

        A caller that cannot tell "could not measure" from "no drift"
        will report a full disk as a clean tree.
        """
        if not SCRIPT.exists():
            self.skipTest(f"baseline check script missing: {SCRIPT}")
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Disk quota exceeded", text)
        self.assertRegex(text, r"exit 2")


if __name__ == "__main__":
    unittest.main()
