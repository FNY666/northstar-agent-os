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
   while CI watched 33,295 -- it never saw the suite's 9,945 standalone
   module-level ``test_*`` functions, in 811 files.  The runner is now
   selectable and defaults to pytest.
3. **The path.**  The runtime job's ``working-directory`` is the
   component, so the step must reach the repository's ``scripts/``.

These tests read the REAL workflow and the REAL script.  They do not
run the suite: the check itself does that, and CI is about to run it.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
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

        This test **RUNS** the selection.  The previous version of it
        compared the string positions of the two paths in the script,
        which proved nothing: ``text.index(authority)`` found the
        occurrence on the script's **header comment**, while the real
        candidate list put the checkout-local copy **first**.  The
        assertion passed and the script did the opposite of what it
        claimed.

        So the selection is exercised against a fixture directory that
        holds BOTH the coordinator's baseline and the checkout-local
        copy, and the file it picks is asserted.
        """
        if not SCRIPT.exists():
            self.skipTest(f"baseline check script missing: {SCRIPT}")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            (home / "docs" / "baseline").mkdir(parents=True)
            authority = home / "authority.failures.txt"
            authority.write_text("# coordinator's authority\n", encoding="utf-8")
            (home / "b173-baseline-CURRENT").write_text(
                authority.name + "\n", encoding="utf-8"
            )
            fallback = home / "docs" / "baseline" / "current.failures.txt"
            fallback.write_text("# checkout-local fallback\n", encoding="utf-8")
            picked = self._select_baseline(home, fallback)
            self.assertEqual(
                picked, authority,
                "the coordinator's baseline must win over the checkout-local "
                "fallback",
            )

    def test_the_script_follows_the_coordinators_current_pointer(self):
        """The authority is named by a POINTER, not by a hardcoded name.

        ``docs/design/r6-baseline-unify.md`` §5.1 says the coordinator
        re-takes the baseline "when main advances" and then "repoints
        b173-baseline-CURRENT at it".  The check script has to follow
        that pointer; a hardcoded filename keeps comparing against a
        retired baseline.

        Measured on this host before the fix: the pointer named a
        26-item baseline, a hardcoded legacy name held 30 items, and the
        newest baseline held ZERO -- so the check would have reported 30
        spurious failures for a tree that is clean.

        So the fixture holds a legacy-named file that IS present, and
        the pointer names a different one: the pointer must win.
        """
        if not SCRIPT.exists():
            self.skipTest(f"baseline check script missing: {SCRIPT}")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            (home / "docs" / "baseline").mkdir(parents=True)
            pointed = home / "b173-baseline-deadbeef.failures.txt"
            pointed.write_text("# the baseline in force\n", encoding="utf-8")
            legacy = home / "b173-baseline-failures-2026-11-14.txt"
            legacy.write_text("# a retired baseline\n", encoding="utf-8")
            (home / "b173-baseline-CURRENT").write_text(
                pointed.name + "\n", encoding="utf-8"
            )
            fallback = home / "docs" / "baseline" / "current.failures.txt"
            fallback.write_text("# checkout-local fallback\n", encoding="utf-8")
            picked = self._select_baseline(home, fallback)
            self.assertEqual(
                picked, pointed,
                "the check must follow b173-baseline-CURRENT, not a "
                "hardcoded baseline filename",
            )

    def test_the_check_falls_back_when_there_is_no_pointer(self):
        """No coordinator directory means the checkout-local copy.

        A CI runner has no ``/home/muse-newapi``, so the in-repo copy is
        the only thing it can compare against -- and it must still be
        found.  The fallback is the repository's own
        ``docs/baseline/current.failures.txt``, which is tracked, so a
        CI checkout has it.
        """
        if not SCRIPT.exists():
            self.skipTest(f"baseline check script missing: {SCRIPT}")
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir(parents=True)
            picked = self._select_baseline(home, LOCAL_BASELINE)
            self.assertEqual(
                picked.resolve(), LOCAL_BASELINE.resolve(),
                "without a coordinator's pointer the checkout-local copy "
                "must be used",
            )

    # -- helpers --------------------------------------------------------

    @staticmethod
    def _select_baseline(coordinator_dir: Path, fallback: Path):
        """Run the script's baseline SELECTION and report which file it picked.

        The selection is exercised without running the suite: the script
        echoes the baseline it chose, and the suite is skipped with
        ``B173_BASELINE_CHECK_SKIP_SUITE=1``.  The script's repository
        root is this repository's, but the baseline candidates are
        redirected with ``B173_BASELINE_DIR`` -- so the fixture
        directory stands in for ``/home/muse-newapi``.
        """
        env = dict(os.environ)
        env["B173_BASELINE_DIR"] = str(coordinator_dir)
        env["B173_BASELINE_CHECK_SKIP_SUITE"] = "1"
        env.pop("B173_BASELINE_FILE", None)
        proc = subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        picked = None
        for line in proc.stdout.splitlines():
            if line.startswith("baseline file: "):
                picked = line.split("baseline file: ", 1)[1].strip()
        if picked is None:
            raise AssertionError(
                "the script did not report a baseline; it said:\n"
                + proc.stdout
                + proc.stderr
            )
        return Path(picked)

    def test_the_default_runner_is_the_one_ci_uses(self):
        """pytest, not unittest.

        unittest's discovery collects only test METHODS inside TestCase
        classes.  The runtime suite has 9,945 standalone module-level
        ``test_*`` functions in 811 files that unittest never sees, so a
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
