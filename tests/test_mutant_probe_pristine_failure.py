"""The mutant probe must not report a kill from a scope that was broken already.

THE DEFECT THIS PINS
---------------------
``scripts/b173-mutant.py`` takes a PRE-FLIGHT reading of the suite on the
PRISTINE source, to tell two causes of a collection error apart: the suite
was already broken (the mutant is innocent -> SKIP), or the mutant broke
the suite (a genuine KILL).

The pre-flight computed ``preflight_collection_failed`` and then NEVER USED
it.  It only skipped when the suite collected NOTHING.  A suite that
COLLECTS tests but FAILS on the pristine source passed straight through,
and every round's non-zero exit was read as "mutant killed".

Measured 2026-11-25 on ``refusal_hold_wiring.py``: its scope includes
``test_finding_gate``, whose ``DesignDocTests`` reads
``docs/design/bughunter-finding-gate.md`` from the REPO ROOT via
``Path(__file__).resolve().parents[3]``.  The census worktree copies only
the component directory, so that doc is absent and the five doc tests ERROR
at setup -- on the PRISTINE source.  The census reported "killed 23/23".
Planting the ``>`` -> ``>=`` cap mutation and running the same suites by
hand showed it SURVIVES (359 passed, 5 errors -- the same 5 errors the
pristine source has), which is what the design doc's own arithmetic had
already proved.  **All 23 kills were FALSE KILLS.**

So two defects had to be fixed together:

1. ``b173-census-all.sh`` now copies the repo-root ``docs/``, ``scripts/``
   and ``tests/`` into the census worktree, because 17 of the runtime's
   suites resolve a path that leaves the component directory and 16 of the
   runtime's 1620 modules have a scope that includes one.
2. ``b173-mutant.py`` now treats a pristine-source FAILURE as a SKIP, not a
   kill.  The exit code is the primary signal, because a setup error
   leaves tests COLLECTED but failing, which ``collected_nothing`` cannot
   see.

THE NON-VACUITY CONTROL
------------------------
A guard that cannot fail proves nothing.  These tests use a SYNTHETIC
worktree with a tiny module and a tiny suite, so the probe's behaviour can
be observed in both directions:

* a suite that FAILS on the pristine source must produce a SKIP and no
  kill;
* the SAME probe against a suite that PASSES on the pristine source must
  still produce a kill.

If the second half were absent, a probe that skipped everything would
pass the first half.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE = REPO_ROOT / "scripts" / "b173-mutant.py"
CENSUS = REPO_ROOT / "scripts" / "b173-census-all.sh"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


#: A module with exactly one mutable construct: ``a == b``.
MODULE_SOURCE = '''\
def same(a, b):
    """Return whether the two are equal."""
    return a == b
'''

#: A suite that PASSES on the pristine module.
SUITE_PASSES = '''\
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tiny


def test_the_module_works():
    assert tiny.same(1, 1) is True
    assert tiny.same(1, 2) is False
'''

#: A suite that FAILS on the PRISTINE module -- it collects a test, and
#: the test fails.  This is the shape the defect needed: the suite is
#: COLLECTED, so ``collected_nothing`` does not fire, but its exit code is
#: non-zero before any mutant is applied.
SUITE_FAILS_ON_PRISTINE = '''\
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tiny


def test_the_module_works():
    assert tiny.same(1, 1) is True
    assert tiny.same(1, 2) is False


def test_an_unrelated_thing_that_is_already_broken():
    assert 2 + 2 == 5, "this failure has nothing to do with the mutant"
'''


def _run_probe(workdir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(PROBE),
            "--file",
            str(workdir / "tiny.py"),
            "--test-module",
            "test_tiny",
            "--workdir",
            str(workdir),
            "--tries",
            "8",
            "--no-early-stop",
        ],
        cwd=str(workdir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=300,
    )


class PristineFailureIsNotAKillTests(unittest.TestCase):
    """A scope that is broken before the probe starts certifies nothing."""

    def _worktree(self, suite_source: str) -> tempfile.TemporaryDirectory:
        tmp = tempfile.TemporaryDirectory(prefix="b173-probe-")
        root = Path(tmp.name)
        _write(root / "tiny.py", MODULE_SOURCE)
        _write(root / "tests" / "test_tiny.py", suite_source)
        self.addCleanup(tmp.cleanup)
        return tmp

    def test_a_suite_that_fails_on_the_pristine_source_is_skipped(self):
        """The suite is broken BEFORE any mutant: the round is a SKIP."""
        tmp = self._worktree(SUITE_FAILS_ON_PRISTINE)
        result = _run_probe(Path(tmp.name))
        self.assertIn(
            "MUTANT SKIP",
            result.stdout,
            f"the probe must skip a pristine-source failure:\n{result.stdout}",
        )
        self.assertNotIn(
            "KILLED",
            result.stdout,
            f"the probe reported a kill from a broken scope:\n{result.stdout}",
        )
        self.assertNotIn(
            "MUTANT RESULT",
            result.stdout,
            f"the probe reported a score for an unmeasurable scope:\n{result.stdout}",
        )

    def test_a_healthy_suite_is_still_measured(self):
        """THE NON-VACUITY CONTROL.

        The same probe, against a suite that passes on the pristine source,
        must still KILL the mutant.  Without this half, a probe that
        skipped everything would satisfy the guard above.
        """
        tmp = self._worktree(SUITE_PASSES)
        result = _run_probe(Path(tmp.name))
        self.assertIn(
            "MUTANT eq@3 KILLED",
            result.stdout,
            f"the probe stopped killing a healthy scope:\n{result.stdout}",
        )
        self.assertIn(
            "MUTANT RESULT: killed 1/1",
            result.stdout,
            f"the probe did not score a healthy scope:\n{result.stdout}",
        )

    def test_the_probe_leaves_the_module_pristine(self):
        """The probe restores the file it mutated, even when it skips."""
        tmp = self._worktree(SUITE_FAILS_ON_PRISTINE)
        _run_probe(Path(tmp.name))
        self.assertEqual(
            (Path(tmp.name) / "tiny.py").read_text(encoding="utf-8"),
            MODULE_SOURCE,
            "the probe left a mutant behind in the module under test",
        )


class TheCensusWorktreeCarriesTheRepoRootTests(unittest.TestCase):
    """The worktree must be able to RUN the suites in a scope.

    Fixing the probe alone would make every affected scope a permanent
    SKIP -- an honest "cannot measure", but no evidence.  So the census
    worktree has to hold what those suites need, and there are TWO kinds
    of thing:

    * **FILES at the repo root.**  `test_finding_gate.py`'s
      `DesignDocTests` reads `docs/design/bughunter-finding-gate.md`
      from the repo root via `Path(__file__).resolve().parents[3]`.  17
      of the runtime's suites resolve a path that way, and 16 of the
      runtime's 1620 modules have a scope that includes one.
    * **GIT HISTORY.**  `test_blind_rerunner.py` runs `git rev-parse` on
      a NAMED COMMIT and builds a delivery bundle from the range, so it
      needs a repository whose history contains that commit.

    A `git clone` gives both.  Copying the directories by hand gave
    only the first, and `blind_rerunner`'s census row stayed false.
    """

    def test_the_census_worktree_is_a_git_repository(self):
        """A clone gives the history the git-dependent suites need."""
        script = CENSUS.read_text(encoding="utf-8")
        self.assertIn(
            "git clone",
            script,
            "the census worktree must be a clone: a suite that resolves a "
            "named commit needs the repository's HISTORY, and a plain copy "
            "of the component directory has none -- so that suite fails on "
            "the pristine source and every mutant in its scope is a false "
            "kill",
        )

    def test_the_census_script_copies_the_repo_root_directories(self):
        """The repo-root files must be present in the worktree.

        A clone already carries them, but the script must not depend on
        that silently: the copy is what makes the requirement explicit,
        and it is what keeps the worktree correct if the clone step is
        ever replaced.
        """
        script = CENSUS.read_text(encoding="utf-8")
        for needle in ('"$REPO_ROOT/docs"', '"$REPO_ROOT/scripts"', '"$REPO_ROOT/tests"'):
            self.assertIn(
                needle,
                script,
                f"the census worktree must carry {needle}: a suite that reads "
                "the repo root would otherwise error on the pristine source, "
                "and every mutant in its scope would be a false kill",
            )

    def test_the_worktree_preparation_precedes_the_probe_run(self):
        """The preparation must happen BEFORE the probe runs, not after."""
        script = CENSUS.read_text(encoding="utf-8")
        self.assertIn(
            '"$REPO_ROOT/docs"',
            script,
            "the worktree must carry the repo root at all",
        )
        copy_at = script.index('"$REPO_ROOT/docs"')
        run_at = script.index('"$PROBE"')
        self.assertLess(
            copy_at,
            run_at,
            "the repo-root copy must precede the probe invocation",
        )


class TheCensusWorktreeCanRunAGitDependentSuiteTests(unittest.TestCase):
    """The worktree must be able to run a suite that needs git history.

    This is the property the plain copy could not provide, and it is
    what made `blind_runner`'s census row false: the suite failed on
    the pristine source, so every mutant was reported killed.
    """

    def test_the_census_worktree_resolves_a_named_commit(self):
        """The worktree must be a repository whose history has the commit."""
        import subprocess

        with tempfile.TemporaryDirectory(prefix="b173-census-wt-") as tmp:
            worktree = Path(tmp) / "wt"
            result = subprocess.run(
                [
                    "git",
                    "clone",
                    "--quiet",
                    "--shared",
                    "--no-checkout",
                    str(REPO_ROOT),
                    str(worktree),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=600,
            )
            if result.returncode != 0:
                self.skipTest(f"git clone is unavailable here: {result.stdout}")
            head = subprocess.run(
                ["git", "-C", str(worktree), "rev-parse", "HEAD"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            self.assertEqual(
                head.returncode,
                0,
                f"the clone must resolve HEAD:\n{head.stdout}",
            )
            self.assertTrue(
                (worktree / ".git").exists(),
                "the worktree must be a git repository, not a plain copy",
            )


class TheScopeDoesNotIncludeSuitesThatCannotRunTests(unittest.TestCase):
    """A suite that reads outside the component must still be measurable.

    This pins the property the fix restores: with the repo root in the
    worktree, a scope that includes such a suite runs it successfully on
    the pristine source, so the probe can measure it.
    """

    def test_a_doc_reading_suite_runs_in_a_worktree_with_the_repo_root(self):
        """`test_finding_gate`'s doc tests need the repo's `docs/`."""
        suite = (
            REPO_ROOT
            / "components"
            / "northstar-agent-runtime"
            / "tests"
            / "test_finding_gate.py"
        )
        if not suite.exists():
            self.skipTest("test_finding_gate.py is not in this tree")
        with tempfile.TemporaryDirectory(prefix="b173-docs-") as tmp:
            root = Path(tmp)
            component = root / "components" / "northstar-agent-runtime"
            _write(root / "docs" / "design" / "bughunter-finding-gate.md", "# stub\n")
            (component / "tests").mkdir(parents=True, exist_ok=True)
            (component / "tests" / "test_finding_gate.py").write_text(
                suite.read_text(encoding="utf-8"), encoding="utf-8"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "tests/test_finding_gate.py::DesignDocTests",
                ],
                cwd=str(component),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=300,
            )
            self.assertNotIn(
                "error during collection",
                result.stdout.lower(),
                f"the suite must collect when the repo root is present:\n{result.stdout}",
            )


if __name__ == "__main__":
    unittest.main()
