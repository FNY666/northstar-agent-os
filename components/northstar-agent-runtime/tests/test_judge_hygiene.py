"""Read-only conformance tests for the mutant probe (``b173-mutant.py`` /
``b173-mutant.sh``).

The probe is the referee's tool for the ``MUTANT`` acceptance item: it
plants small semantic faults in a slice's module and asks the slice's own
tests whether they notice.  Two defects made its verdict untrustworthy:

* **D-22 (bytecode cache).**  The probe rewrote the module in place and
  then ran the tests.  A ``.pyc`` is considered valid when the source's
  ``(mtime seconds, byte size)`` matches the cache entry.  ``or -> and``
  and ``> -> >=`` are *same-length* rewrites, so two rounds landing in the
  same second produced an identical cache criterion -- Python re-used the
  previous round's bytecode and the probe silently ran the *previous*
  mutant.  The verdict then depended on a wall-clock boundary.
* **D-23 (commit pinning).**  The probe's worktree was pinned to the
  slice's own last commit.  A fix that landed under a different slug
  prefix was invisible, so the probe reported "all mutants survived"
  forever.

These tests assert the *behaviour* of the probe, not the text of its
source.  The probe lives outside the repository, so the behavioural tests
run against a copy of the installed probe with this slice's patch applied
(when the installed probe has not been patched yet) and skip cleanly when
the probe is not installed at all.  At least one test depends only on
in-repository files.

Nothing here mutates the repository: the probe is exercised against
throwaway directories under ``tempfile.mkdtemp()`` that are removed again.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
PROBE_PY = Path("/home/muse-newapi/b173-mutant.py")
PROBE_SH = Path("/home/muse-newapi/b173-mutant.sh")
# The probe as it was BEFORE the judge-hygiene patch was applied.  The
# patch-application test below needs that version as its "before" side:
# once the coordinator has applied the patch to the live probe, `patch`
# correctly reports "Reversed (or previously applied)" and the test would
# fail for a reason unrelated to what it checks.  The pre-round-6 copies
# are kept for exactly this purpose (see b173-accept.sh.preround6).
PROBE_PY_BASE = Path("/home/muse-newapi/b173-mutant.py.preround6")
PROBE_SH_BASE = Path("/home/muse-newapi/b173-mutant.sh.preround6")
PATCH_FILE = Path("/home/muse-newapi/b173-judge-hygiene-fix.patch")
DESIGN_DOC = REPO_ROOT / "docs" / "design" / "judge-hygiene.md"

# The two behavioural fixes of this slice, as exact old -> new text.  They
# are applied to a *copy* of the installed probe by the tests below, so the
# behavioural tests are meaningful whether or not the coordinator has
# applied the live patch yet.  The live probe is never modified.
BEHAVIOUR_FIXES = (
    (
        '    env = dict(os.environ)\n'
        '    env["PYTHONPATH"] = ".:tests"\n',
        '    env = dict(os.environ)\n'
        '    env["PYTHONPATH"] = ".:tests"\n'
        '    env["PYTHONDONTWRITEBYTECODE"] = "1"\n',
    ),
    (
        '        with open(a.file, "w", encoding="utf-8") as f:\n'
        '            f.write(trial_src)\n',
        '        purge_bytecode(a.file)\n'
        '        with open(a.file, "w", encoding="utf-8") as f:\n'
        '            f.write(trial_src)\n',
    ),
    (
        '        with open(a.file, "w", encoding="utf-8") as f:\n'
        '            f.write(orig)\n',
        '        purge_bytecode(a.file)\n'
        '        with open(a.file, "w", encoding="utf-8") as f:\n'
        '            f.write(orig)\n',
    ),
)

PURGE_HELPER = '''def purge_bytecode(path):
    """Remove any cached bytecode for `path` so a rewritten source is
    recompiled."""
    cache = os.path.join(os.path.dirname(os.path.abspath(path)), "__pycache__")
    if not os.path.isdir(cache):
        return
    stem = os.path.splitext(os.path.basename(path))[0]
    for name in os.listdir(cache):
        if name.startswith(stem + ".") and name.endswith(".pyc"):
            try:
                os.remove(os.path.join(cache, name))
            except OSError:
                pass

def run_tests(workdir, test_module, timeout=180):'''

# The D-22 fix may already be present in the installed probe under a
# different helper name (the round-5 flow optimisation named it
# ``drop_cached_bytecode``); the behavioural tests only care that the
# stale bytecode is dropped, not what the helper is called.
_D22_MARKERS = ("PYTHONDONTWRITEBYTECODE", "drop_cached_bytecode",
                "purge_bytecode")

# The fixture module holds two *same-length* boolean rewrites on different
# lines, and the fixture tests distinguish them: the first rewrite is
# detected by the suite, the second one is not covered by any test.
FIXTURE_MODULE = (
    "def pick(flag, other):\n"
    "    if flag or other:\n"
    "        return 'first'\n"
    "    return 'second'\n"
    "\n"
    "\n"
    "def pick_other(flag, other):\n"
    "    if flag or other:\n"
    "        return 'alpha'\n"
    "    return 'beta'\n"
)
FIXTURE_TEST = (
    "import unittest\n"
    "\n"
    "from probe_mod import pick\n"
    "\n"
    "\n"
    "class ProbeTests(unittest.TestCase):\n"
    "    def test_first_branch(self):\n"
    "        self.assertEqual(pick(True, False), 'first')\n"
    "\n"
    "    def test_second_branch(self):\n"
    "        self.assertEqual(pick(False, False), 'second')\n"
    "\n"
    "\n"
    "if __name__ == '__main__':\n"
    "    unittest.main()\n"
)


def _write_fixture(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "probe_mod.py").write_text(FIXTURE_MODULE, encoding="utf-8")
    (root / "test_probe_mod.py").write_text(FIXTURE_TEST, encoding="utf-8")
    return root


def _run_probe(probe: Path, workdir: Path, env_extra=None, tries=3,
               no_early_stop=False):
    """Run the probe against a throwaway workdir; return (rc, stdout).

    ``no_early_stop`` asks the probe to try every candidate instead of
    stopping at the first kill.  The behavioural tests below NEED more than
    one verdict -- they assert that a KILLED and a SURVIVED verdict are both
    reported, which is how they prove each round measured that round's code
    and not a stale one.  The judge's own use of the probe stops at the
    first kill, because its contract is only ">=1 killed".
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = ".:tests"
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, str(probe),
         "--file", str(workdir / "probe_mod.py"),
         "--test-module", "test_probe_mod",
         "--workdir", str(workdir),
         "--tries", str(tries)] + (["--no-early-stop"] if no_early_stop else []),
        cwd=str(workdir), env=env, timeout=300,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode, proc.stdout


def _result_line(stdout: str) -> str:
    for line in stdout.splitlines():
        if line.startswith("MUTANT RESULT:"):
            return line
    return ""


def _killed_count(stdout: str) -> int:
    line = _result_line(stdout)
    if "killed " not in line:
        return -1
    return int(line.split("killed ")[1].split("/")[0])


def _mutant_lines(stdout: str):
    return [ln for ln in stdout.splitlines()
            if ln.startswith("MUTANT ") and " RESULT" not in ln]


def _patched_probe_copy(tmpdir: Path) -> Path:
    """Copy the installed probe and apply the behavioural fixes to the copy.

    The live probe is the referee's tool and is *not* edited by this
    slice; the coordinator applies the patch.  To keep these tests
    meaningful before and after that happens, the behavioural tests run
    against a copy of the installed probe carrying this slice's fixes.
    When the installed probe already carries them, the copy is used
    as-is.
    """
    if not PROBE_PY.exists():
        raise unittest.SkipTest(f"probe not installed at {PROBE_PY}")
    source = PROBE_PY.read_text(encoding="utf-8")
    if not any(marker in source for marker in _D22_MARKERS):
        source = source.replace(
            "def run_tests(workdir, test_module, timeout=180):",
            PURGE_HELPER, 1,
        )
        for old, new in BEHAVIOUR_FIXES:
            if old not in source:
                raise unittest.SkipTest(
                    "the installed probe does not have the expected shape "
                    "for this slice's fix"
                )
            source = source.replace(old, new, 1)
    copy = tmpdir / "b173-mutant.py"
    copy.write_text(source, encoding="utf-8")
    return copy


class JudgeHygieneRepoDocTests(unittest.TestCase):
    """Tests that depend only on files inside the repository."""

    def test_design_doc_exists_and_records_the_before_after_table(self):
        self.assertTrue(
            DESIGN_DOC.exists(),
            f"design doc missing: {DESIGN_DOC}",
        )
        text = DESIGN_DOC.read_text(encoding="utf-8")
        self.assertIn("Before/after", text)
        self.assertIn("MUTANT RESULT", text)

    def test_design_doc_names_both_defects_and_the_change_spec(self):
        if not DESIGN_DOC.exists():
            self.skipTest(f"design doc missing: {DESIGN_DOC}")
        text = DESIGN_DOC.read_text(encoding="utf-8")
        self.assertIn("PYTHONDONTWRITEBYTECODE", text)
        self.assertIn("MUTANT NOTE", text)
        self.assertIn("b173-mutant.py", text)
        self.assertIn("b173-mutant.sh", text)

    def test_design_doc_states_the_tradeoff_against_pinning_head(self):
        if not DESIGN_DOC.exists():
            self.skipTest(f"design doc missing: {DESIGN_DOC}")
        text = DESIGN_DOC.read_text(encoding="utf-8")
        self.assertIn("pin HEAD", text)
        self.assertIn("Tradeoff", text)

    def test_design_doc_lists_the_slices_whose_mutant_verdict_changes(self):
        if not DESIGN_DOC.exists():
            self.skipTest(f"design doc missing: {DESIGN_DOC}")
        text = DESIGN_DOC.read_text(encoding="utf-8")
        for slug in ("vina", "tombstone"):
            self.assertIn(slug, text)


class JudgeHygieneProbeBehaviourTests(unittest.TestCase):
    """Behavioural tests against the mutant probe.

    The probe lives outside the repository; every test below builds a
    throwaway directory, runs the probe in it and removes the directory
    again.  Nothing is written into the repository.
    """

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="b173-judge-hygiene-"))
        self.addCleanup(shutil.rmtree, self._tmp, True)
        self.probe = _patched_probe_copy(self._tmp)

    def _workdir(self, name="wd"):
        return _write_fixture(self._tmp / name)

    def test_two_same_length_mutants_written_in_the_same_second_are_both_seen(self):
        """(a) The probe must observe the *second* mutant, not the first.

        The probe rewrites the module and runs the tests once per mutant.
        Two same-length rewrites inside the same second produce an
        identical ``(mtime, size)`` cache criterion, so a probe that
        leaves the old ``.pyc`` in place runs the previous round's code
        and reports the previous round's verdict a second time.
        """
        wd = self._workdir()
        rc, out = _run_probe(self.probe, wd, no_early_stop=True)
        self.assertIn("MUTANT RESULT:", out, out)
        lines = _mutant_lines(out)
        self.assertGreaterEqual(len(lines), 2, out)
        verdicts = [ln.split(" ")[2] for ln in lines]
        # The two rewrites must not be judged by the same round's code:
        # one branch is covered by the suite, the other is not.
        self.assertIn("KILLED", verdicts, out)
        self.assertIn("SURVIVED", verdicts, out)

    def test_probe_does_not_reuse_stale_bytecode_after_rewriting(self):
        """(b) After the probe rewrites the module, no stale ``.pyc`` may
        be left next to it for the next round to inherit."""
        wd = self._workdir()
        _run_probe(self.probe, wd)
        cache = wd / "__pycache__"
        stale = sorted(p.name for p in cache.glob("probe_mod.*.pyc")) if cache.exists() else []
        self.assertEqual(
            stale, [],
            "probe left a bytecode cache entry for the module it rewrote",
        )

    def test_probe_writes_no_bytecode_cache_for_the_rewritten_module(self):
        """(b, second angle) The probe's test runs must not leave a
        ``.pyc`` next to the module it mutates."""
        wd = self._workdir()
        _run_probe(self.probe, wd)
        cache = wd / "__pycache__"
        leftovers = sorted(p.name for p in cache.glob("probe_mod.*")) if cache.exists() else []
        self.assertEqual(leftovers, [], f"stale bytecode left behind: {leftovers}")

    def test_killed_count_is_identical_across_two_runs_on_the_same_code(self):
        """(c) The reported ``killed k/3`` must be reproducible."""
        wd = self._workdir()
        rc1, out1 = _run_probe(self.probe, wd)
        rc2, out2 = _run_probe(self.probe, wd)
        self.assertEqual(
            _result_line(out1), _result_line(out2),
            f"probe verdict is not reproducible:\n{out1}\n---\n{out2}",
        )
        self.assertEqual(rc1, rc2, out1 + out2)

    def test_killed_count_is_identical_with_and_without_a_bytecode_cache(self):
        """(c, second angle) The verdict must not depend on whether the
        interpreter is allowed to write bytecode."""
        wd = self._workdir()
        _, out_def = _run_probe(self.probe, wd)
        _, out_noc = _run_probe(self.probe, wd, env_extra={"PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(
            _result_line(out_def), _result_line(out_noc),
            f"verdict depends on the bytecode cache:\n{out_def}\n---\n{out_noc}",
        )

    def test_probe_output_format_is_unchanged(self):
        """(d) ``b173-accept.sh`` keys off this output, so the format is
        part of the contract."""
        wd = self._workdir()
        rc, out = _run_probe(self.probe, wd)
        lines = _mutant_lines(out)
        self.assertTrue(lines, out)
        for line in lines:
            self.assertRegex(
                line,
                r"^MUTANT (eq|gt|lt|retT|retF|and|or)@\d+ "
                r"(KILLED|SURVIVED|SKIP) \(.+\)$",
                f"unexpected probe output line: {line!r}",
            )
        self.assertRegex(
            _result_line(out),
            r"^MUTANT RESULT: killed \d+/\d+$",
            out,
        )

    def test_probe_exit_code_semantics_are_unchanged(self):
        """(d) 0 = at least one mutant killed, 1 = all survived, 2 = the
        probe could not run."""
        wd = self._workdir()
        rc, out = _run_probe(self.probe, wd)
        killed = _killed_count(out)
        if killed >= 1:
            self.assertEqual(rc, 0, out)
        elif killed == 0:
            self.assertEqual(rc, 1, out)
        else:
            self.assertEqual(rc, 2, out)

    def test_probe_restores_the_original_source_after_each_round(self):
        """The probe must leave the module byte-identical to the original."""
        wd = self._workdir()
        module = wd / "probe_mod.py"
        before = module.read_bytes()
        _run_probe(self.probe, wd)
        self.assertEqual(module.read_bytes(), before)

    def test_probe_restores_the_original_source_when_it_is_killed(self):
        """A probe that is KILLED mid-round must still restore the module.

        This is the D-24 defect.  The probe writes a mutant into the
        module, runs the suite, then restores the original.  If the
        process dies between the write and the restore -- a wall-clock
        timeout, a SIGTERM from a batch runner -- the module is left
        MUTATED, and the NEXT run measures a contaminated tree.

        The contamination is not a harmless leftover.  Measured
        2026-11-22: a census run killed mid-flight left two mutations in
        ``merged_tree_review.py``; the next run then reported "killed
        37/37" with zero survivors, because those two leftover mutants
        broke four UNRELATED tests.  The committed record said
        "killed 37/39" with two genuine survivors.  So the leftover
        produced a FALSE KILL in the opposite direction from the one the
        stale-bytecode defect produced -- and a census that reads "no
        survivors" off a contaminated tree is exactly as untrustworthy as
        one that reads "all survived" off a stale one.

        The restore must therefore survive a signal, not just a normal
        return.  The fixture below has a deliberately SLOW test, so the
        probe is provably still inside a round when the signal lands;
        otherwise the test could pass without ever exercising the defect.
        """
        wd = self._tmp / "slow"
        wd.mkdir(parents=True, exist_ok=True)
        (wd / "probe_mod.py").write_text(FIXTURE_MODULE, encoding="utf-8")
        (wd / "test_probe_mod.py").write_text(
            "import time\n"
            "import unittest\n\n"
            "from probe_mod import pick\n\n\n"
            "class ProbeTests(unittest.TestCase):\n"
            "    def test_slow(self):\n"
            "        time.sleep(20)\n"
            "        self.assertEqual(pick(True, False), 'first')\n\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
            encoding="utf-8",
        )
        module = wd / "probe_mod.py"
        before = module.read_bytes()
        env = dict(os.environ)
        env["PYTHONPATH"] = ".:tests"
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        proc = subprocess.Popen(
            [sys.executable, str(self.probe),
             "--file", str(module),
             "--test-module", "test_probe_mod",
             "--workdir", str(wd),
             "--tries", "64", "--no-early-stop"],
            cwd=str(wd), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            # The probe must still be running: the fixture's suite sleeps
            # for 20 seconds, so a probe that has already exited did not
            # exercise the defect.
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            pass
        else:
            proc.communicate()
            self.skipTest("the probe finished before it could be killed")
        proc.terminate()
        try:
            proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
        self.assertEqual(
            module.read_bytes(), before,
            "the probe was killed mid-round and left the module mutated",
        )

    def test_probe_reports_skips_with_exit_code_two_when_nothing_is_mutable(self):
        """2 = the probe could not run (no mutable construct found)."""
        wd = self._tmp / "empty"
        wd.mkdir(parents=True, exist_ok=True)
        (wd / "probe_mod.py").write_text("VALUE = 1\n", encoding="utf-8")
        (wd / "test_probe_mod.py").write_text(
            "import unittest\n\n\nclass T(unittest.TestCase):\n"
            "    def test_nothing(self):\n        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        rc, out = _run_probe(self.probe, wd)
        self.assertEqual(rc, 2, out)
        self.assertIn("MUTANT SKIP", out)

    def test_probe_script_files_exist_and_are_executable(self):
        """(d) The tool scripts must still be present and executable."""
        for path in (PROBE_PY, PROBE_SH):
            if not path.exists():
                self.skipTest(f"probe not installed at {path}")
            self.assertTrue(os.access(path, os.X_OK), f"{path} is not executable")

    def test_wrapper_script_keeps_its_exit_code_semantics(self):
        """(d) The shell wrapper must forward the probe's exit code."""
        if not PROBE_SH.exists():
            self.skipTest(f"probe not installed at {PROBE_SH}")
        text = PROBE_SH.read_text(encoding="utf-8")
        self.assertIn("exit $RC", text)
        # The D-23 fallback is either already applied to the installed
        # wrapper or still waiting in this slice's patch.
        patched = PATCH_FILE.exists() and "MUTANT NOTE" in PATCH_FILE.read_text(
            encoding="utf-8")
        self.assertTrue("MUTANT NOTE" in text or patched,
                        "the commit-pinning fallback is neither applied nor "
                        "present in this slice's patch")


class JudgeHygieneCensusPairingTests(unittest.TestCase):
    """The census script must pair each module with the suite that tests it.

    The census script (``scripts/b173-census-all.sh``) used to pass
    ``--test-module test_cancellation_gate`` for EVERY module it was
    pointed at.  A module that suite does not exercise is therefore
    measured with the wrong tests, and every mutant in it "survives" --
    a false accusation of a weak test suite.

    Measured 2026-11-22: with the hardcoded suite a census of
    ``merged_tree_review.py`` reported "killed 0/8"; with the module's
    own suite it reports "killed 37/39".
    """

    CENSUS = REPO_ROOT / "scripts" / "b173-census-all.sh"

    def setUp(self):
        if not self.CENSUS.exists():
            self.skipTest(f"census script missing: {self.CENSUS}")
        self.text = self.CENSUS.read_text(encoding="utf-8")

    def test_the_census_script_is_in_the_repository(self):
        """The census tooling must be reachable from a fresh clone."""
        self.assertTrue(self.CENSUS.exists(), str(self.CENSUS))

    def test_the_census_script_pairs_a_module_with_its_own_test_file(self):
        """No hardcoded test module may be applied to every module."""
        self.assertNotIn(
            "--test-module test_cancellation_gate", self.text,
            "the census still measures every module with the same suite",
        )

    def test_the_census_script_names_the_module_it_is_censusing(self):
        """The pairing must be derived from the module's own basename."""
        self.assertIn("MODBASE=$(basename", self.text)
        self.assertIn("test_${MODBASE}.py", self.text)

    def test_the_census_script_restores_the_module_after_each_census(self):
        """An interrupted census must not contaminate the next one."""
        self.assertIn(
            'cp "$RUNTIME_DIR/$m" "$MODPATH"', self.text,
            "the census does not restore the module from the pristine source",
        )

    def test_the_repo_probe_carries_the_crash_safe_restore(self):
        """The probe in the repository must restore on a signal.

        The live probe lives outside the repository, so a fresh clone
        would otherwise get a census script with no probe to run.
        """
        probe = REPO_ROOT / "scripts" / "b173-mutant.py"
        if not probe.exists():
            self.skipTest(f"probe missing: {probe}")
        source = probe.read_text(encoding="utf-8")
        self.assertIn("atexit.register", source,
                      "the repo probe has no atexit restore")
        self.assertIn("signal.signal", source,
                      "the repo probe has no signal handler")
        self.assertIn("restore_original", source,
                      "the repo probe has no restore helper")


class JudgeHygienePatchTests(unittest.TestCase):
    """Tests on this slice's own patch file (outside the repository)."""

    def setUp(self):
        if not PATCH_FILE.exists():
            self.skipTest(f"patch file missing: {PATCH_FILE}")
        self._tmp = Path(tempfile.mkdtemp(prefix="b173-judge-hygiene-patch-"))
        self.addCleanup(shutil.rmtree, self._tmp, True)

    def test_patch_applies_cleanly_to_the_installed_probe(self):
        # Use the PRE-patch probe as the "before" side when it is
        # available, so this test keeps its meaning whether or not the
        # coordinator has applied the patch yet.  Fall back to the live
        # probe when the base is absent.
        base_py = PROBE_PY_BASE if PROBE_PY_BASE.exists() else PROBE_PY
        base_sh = PROBE_SH_BASE if PROBE_SH_BASE.exists() else PROBE_SH
        if not base_py.exists():
            self.skipTest(f"probe not installed at {base_py}")
        shutil.copyfile(base_py, self._tmp / "b173-mutant.py")
        if base_sh.exists():
            shutil.copyfile(base_sh, self._tmp / "b173-mutant.sh")
        proc = subprocess.run(
            ["patch", "-p1", "--dry-run", "--batch", "-i", str(PATCH_FILE)],
            cwd=str(self._tmp), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_patch_touches_no_other_file(self):
        text = PATCH_FILE.read_text(encoding="utf-8")
        touched = set()
        for line in text.splitlines():
            for prefix in ("--- a/", "+++ b/"):
                if line.startswith(prefix):
                    touched.add(line[len(prefix):].split("\t")[0].strip())
        self.assertTrue(touched, "the patch names no file")
        self.assertTrue(touched <= {"b173-mutant.py", "b173-mutant.sh"},
                        f"the patch touches other files: {touched}")
        self.assertNotIn("b173-accept.sh", text)
        self.assertNotIn("b173-report-numbers.py", text)
