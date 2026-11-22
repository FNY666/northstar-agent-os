"""The baseline check must tell an environmental failure from a code failure.

THE DEFECT (measured 2026-11-22)
--------------------------------
``scripts/b173-baseline-check.sh`` compares the runtime suite's failure
set against a stored baseline.  Its output is a verdict: "BASELINE
MATCH" or "BASELINE DRIFT".  DRIFT reads as *the code regressed*.

But the runtime suite writes its scratch under ``/tmp``, and ``/tmp`` is
a **tmpfs**.  When the tmpfs fills up, tests that have nothing to do
with the code under test fail with:

    OSError: [Errno 122] Disk quota exceeded

Measured 2026-11-22, with ``/tmp`` at 79% full, the check reported
four such errors as DRIFT:

    > ERROR: test_listing_caps_at_500_entries (test_tools.CapTests...)
    > ERROR: test_read_is_capped_at_256kb_and_says_so (test_tools.CapTests...)
    > ERROR: test_a_copy_of_only_the_component_would_not_be_a_green_baseline
    > ERROR: test_the_source_fleet_shape_reproduces_the_source_rates

All four pass in isolation; the whole component tree is unchanged
between the two runs.  The check could not tell "the disk is full" from
"the code broke" -- and reported the first as the second.

WHAT THIS TEST PINS
--------------------
The check must REFUSE to measure (exit 2) rather than report drift
(exit 1) when

* ``/tmp`` is nearly full before the run, or
* the run itself hit "Disk quota exceeded".

A refusal is not a pass: exit 2 is distinct from both MATCH and
DRIFT, so a caller cannot mistake "could not measure" for "no drift".

These tests exercise the script's own logic against synthetic inputs.
The full suite takes minutes, so the tests do not run it; they check
the script's DECISION, which is where the defect was.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "b173-baseline-check.sh"


def _fake_df(directory: Path, available_kb: str) -> Path:
    """A ``df`` that reports a chosen amount of free space on /tmp."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "df"
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-Pk" ] && [ "$2" = "/tmp" ]; then\n'
        '  echo "Filesystem 1024-blocks Used Available Capacity Mounted on"\n'
        f'  echo "tmpfs 12000000 11800000 {available_kb} 99% /tmp"\n'
        "  exit 0\n"
        "fi\n"
        'exec /usr/bin/df "$@"\n',
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return directory


class BaselineCheckEnvironmentalFailuresTests(unittest.TestCase):
    """The check must not report a full tmpfs as code drift."""

    def setUp(self):
        if not SCRIPT.exists():
            self.skipTest(f"baseline check script missing: {SCRIPT}")
        self._tmp = Path(tempfile.mkdtemp(prefix="b173-baseline-env-"))
        self.addCleanup(shutil.rmtree, self._tmp, True)
        # A baseline that matches nothing, so a run that DOES measure
        # would report drift -- the point is to see whether it measures
        # at all.
        self.baseline = self._tmp / "baseline.txt"
        self.baseline.write_text(
            "FAIL: a_nonexistent_test (test_nonexistent.TestCase.test_x)\n",
            encoding="utf-8",
        )

    def _run(self, fake_df: Path | None = None):
        env = dict(os.environ)
        env["B173_BASELINE_CHECK_SKIP_SUITE"] = "1"
        if fake_df is not None:
            env["PATH"] = f"{fake_df}:{env['PATH']}"
        proc = subprocess.run(
            ["bash", str(SCRIPT), str(self.baseline)],
            env=env, capture_output=True, text=True, timeout=1800,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def test_a_nearly_full_tmpfs_is_refused_not_reported_as_drift(self):
        """DRIFT reads as "the code regressed".  A full disk is not that."""
        fake = _fake_df(self._tmp / "bin", "200000")  # ~195 MiB free
        rc, out = self._run(fake)
        self.assertEqual(rc, 2, out)
        self.assertNotIn("BASELINE DRIFT", out, out)
        self.assertIn("Disk quota exceeded", out, out)

    def test_a_roomy_tmpfs_is_not_refused(self):
        """The guard must not refuse a run that CAN be measured."""
        fake = _fake_df(self._tmp / "bin2", "8000000")  # ~7.6 GiB free
        rc, out = self._run(fake)
        self.assertNotEqual(
            rc, 2,
            f"a tmpfs with plenty of room was refused: {out}",
        )
        self.assertIn("BASELINE DRIFT", out, out)

    def test_the_refusal_and_the_drift_are_distinguishable(self):
        """Exit 2 is neither MATCH (0) nor DRIFT (1).

        A caller that cannot tell "could not measure" from "no drift"
        will report a full disk as a clean tree.
        """
        full = _fake_df(self._tmp / "bin3", "200000")
        rc_full, _ = self._run(full)
        self.assertEqual(rc_full, 2)
        roomy = _fake_df(self._tmp / "bin4", "8000000")
        rc_roomy, _ = self._run(roomy)
        self.assertEqual(rc_roomy, 1)
        self.assertNotEqual(rc_full, rc_roomy)


class BaselineCheckRunnerTests(unittest.TestCase):
    """The check must watch the SAME suite CI watches.

    CI runs the component suite with ``pytest -q tests``.  The check ran
    it with ``python -m unittest <modules>``, and unittest's discovery
    finds only test METHODS inside TestCase classes -- it does not see
    the suite's 9,815 standalone module-level ``test_*`` functions.

    Measured 2026-11-22: unittest discovery collects 23,171 tests and
    pytest collects 33,295.  The check was watching 70% of the suite,
    and the two runners disagreed about what "the suite" is.

    The runner is now selectable and defaults to pytest.
    """

    def setUp(self):
        if not SCRIPT.exists():
            self.skipTest(f"baseline check script missing: {SCRIPT}")
        self.text = SCRIPT.read_text(encoding="utf-8")

    def test_the_default_runner_is_the_one_ci_uses(self):
        self.assertIn(
            'RUNNER="${B173_BASELINE_RUNNER:-pytest}"', self.text,
            "the check does not default to the runner CI uses",
        )

    def test_both_runners_are_available(self):
        self.assertIn("B173_BASELINE_RUNNER=unittest", self.text,
                      "the legacy unittest runner was dropped")
        self.assertIn("python3 -m pytest -q tests", self.text,
                      "the pytest runner is not wired")

    def test_the_runners_failures_are_normalised_to_one_shape(self):
        """A baseline file is comparable against either runner.

        unittest prints "FAIL: test_x (test_mod.TestClass)"; pytest
        prints "FAILED tests/test_mod.py::Class::test_x".  Both must
        reduce to one "<KIND>|<item>" line, or a baseline taken with one
        runner can never be compared against the other.
        """
        self.assertIn('sed -E \'s/^(FAIL|ERROR): [^ ]+ \\(([^)]*)\\)$/\\1|\\2/\'', self.text)
        self.assertIn("\\1|\\2.\\3/", self.text)

    def test_the_check_finds_a_baseline_in_the_repository(self):
        """A CI runner has no /home/muse-newapi.

        The authority file lives outside the repository, so without a
        checkout-local copy the check cannot run off this machine at
        all -- which is most of why A-7 was never wired up.
        """
        self.assertIn("docs/baseline/current.failures.txt", self.text)
        local = REPO_ROOT / "docs" / "baseline" / "current.failures.txt"
        self.assertTrue(local.exists(), f"missing checkout-local baseline: {local}")

    def test_the_check_still_prefers_the_coordinators_file(self):
        """The in-repo copy must not become the authority.

        Re-taking a baseline is the coordinator's decision
        (r6-baseline-unify §5.1), so the coordinator's file must win
        when it exists.

        This used to compare the *string positions* of the two paths in
        the script, which proved nothing: ``text.index(authority)``
        found the occurrence on the script's **header comment**, while
        the real candidate list put the checkout-local copy **first**.
        The assertion passed and the script did the opposite of what it
        claimed.  The selection is now exercised by RUNNING it, in
        ``tests/test_baseline_check_ci_wiring.py`` -- where the probe
        lives, so there is one of it.
        """
        from tests.test_baseline_check_ci_wiring import BaselineCheckPrerequisitesTests

        self.assertIn("b173-baseline-CURRENT", self.text)
        probe = BaselineCheckPrerequisitesTests(
            "test_the_script_prefers_the_coordinators_file_when_present"
        )
        probe.test_the_script_prefers_the_coordinators_file_when_present()


class BaselineCheckQuotaDetectionTests(unittest.TestCase):
    """The script's own log must be scanned for the quota failure."""

    def test_the_script_scans_its_own_log_for_the_quota_error(self):
        """The pre-flight check catches a tmpfs that was ALREADY full.

        A quota can also be reached DURING the run, by the suite's own
        scratch, after the pre-flight check passed.  So the log must be
        scanned too.
        """
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'grep -q "Disk quota exceeded" "$SUITE_LOG"', text,
            "the script does not scan its own log for the quota failure",
        )

    def test_the_quota_check_comes_before_the_comparison(self):
        """The refusal must happen BEFORE any drift is reported.

        The header comment mentions "BASELINE DRIFT" too, so the test
        looks for the *echo* that reports it -- the line the script
        actually prints -- rather than the first occurrence of the word.
        """
        text = SCRIPT.read_text(encoding="utf-8")
        quota_at = text.find('grep -q "Disk quota exceeded" "$SUITE_LOG"')
        drift_at = text.find('echo "BASELINE DRIFT')
        self.assertNotEqual(quota_at, -1)
        self.assertNotEqual(drift_at, -1)
        self.assertLess(
            quota_at, drift_at,
            "the quota check must come before the drift is reported",
        )

    def test_the_preflight_check_refuses_before_running_the_suite(self):
        """A refusal must not cost a full-suite run."""
        text = SCRIPT.read_text(encoding="utf-8")
        guard_at = text.find("BASELINE CHECK ERROR: /tmp has only")
        suite_at = text.find("python3 -m unittest $MODS")
        self.assertNotEqual(guard_at, -1)
        self.assertNotEqual(suite_at, -1)
        self.assertLess(
            guard_at, suite_at,
            "the tmpfs guard must run before the suite does",
        )


if __name__ == "__main__":
    unittest.main()
