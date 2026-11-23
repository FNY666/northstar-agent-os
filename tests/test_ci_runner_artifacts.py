"""No component test may FAIL because the coordinator's directory is absent.

THE DEFECT (measured 2026-11-22)
--------------------------------
The B173 slice chain added tests to the runtime component that read
artifacts living **outside the repository**, in the coordinator's
directory ``/home/muse-newapi``:

    census-parallel-corrected.txt, census-parallel.txt, census-v3.txt
    k3-remeasure.txt, k3-blind-rows.txt, k3-bash-pins.txt
    b173-*.files            (104 slice manifests)
    b173-*-cc-prompt-rerun.md   (the taskbooks)
    b173-accept.sh          (the referee)
    b173-r6-baseline-unify-fix.patch

A GitHub runner has **none** of them: the checkout is the only thing it
has.  Measured under a faithful simulation of a runner (the whole
coordinator directory absent, the repository subtree present), the
component suite produced **18 failures across 7 files** -- and the
``agent-runtime`` CI job runs exactly ``python -m pytest -q tests``, so
**CI was red on every run of this branch**.

The local suite said nothing about this: on the coordinator's machine
every artifact is present, so every test passed.

TWO SHAPES OF THE SAME DEFECT
------------------------------
1. **A crash instead of a skip.**  ``_census_path()`` returns ``None``
   when no census is available, and the caller did
   ``scope, path = _census_path()`` -- so the ABSENCE of an optional
   artifact raised ``TypeError: cannot unpack non-iterable NoneType``.
   Six of the nine coverage-guard failures predated the hardening
   commit; the hardening added three more tests to the same class.
2. **A missing guard.**  Several tests read their artifact
   unconditionally, or guarded only one of the tests in a class.

THE RULE PINNED HERE
---------------------
> **A test that reads an artifact outside the repository SKIPS when that
> artifact is absent.**  It does not fail, and it does not crash.

And, the rule that came with it, which is the harder half:

> **A check whose artifact is a MEASUREMENT must RUN on a runner.**
> The repository holds a copy of every measurement, so a skip there
> means the check silently stopped checking.

WHAT THIS TEST DOES
-------------------
It **runs** the files that read the coordinator's directory, with the
coordinator's directory simulated as absent, and asserts that:

* none of them **fails**;
* none of the measurement-backed ones **skips**;
* every group that was supposed to run **did** run -- under
  ``unittest``, which is in the standard library and therefore present
  in **every** CI job, including the ``documentation`` job that
  installs no dependencies.

The simulation is a ``sitecustomize.py`` that makes ``Path.exists`` /
``is_file`` / ``open`` under the coordinator's directory fail, and makes
``os.scandir`` of it return nothing -- so a ``Path.glob`` there finds
no manifest, exactly as on a runner.

FOUR HOLES THIS GUARD HAD, EACH FOUND BY USING IT
--------------------------------------------------
It is worth writing down, because each one is the same defect in a new
costume -- **the guard measured the wrong thing and read the
measurement as a verdict**:

1. **The wrong runner.**  It ran both suites under ``pytest``.  The
   ``documentation`` CI job installs no dependencies, so ``pytest`` does
   not exist there; the run exited non-zero with no ``FAILED`` line,
   and the "no failures" assertion **passed on a run that collected
   nothing**.  Every file this guard runs is ``TestCase``-based with no
   standalone module-level test functions (verified by AST over all
   23), so ``unittest`` -- in the standard library, present in **every**
   job -- collects the same tests.  Both groups now run under
   ``unittest``, and "the runner is missing" can no longer happen.
2. **A skip was invisible.**  pytest prints skip reasons only under
   ``-rs``; under ``-q`` a skip is a count.  Under ``unittest -v`` the
   reason is on the line after the test id, so the guard carries the
   current id forward and names the tests that skipped.
3. **"Ran 6 tests" was read as six passes.**  unittest's "Ran N"
   counts skipped tests too.  The count is now ``Ran N`` minus the
   skipped.
4. **A legitimate skip could not be told from a lost copy.**  The
   coordinator's *live state* (the referee, the probe, the taskbooks,
   the manifests) has no copy and must skip; the coordinator's
   *measurements* have a copy and must run.  The guard now enforces the
   second and tolerates the first.

A fifth hole, of the same family: the guard decided that a run had
collected nothing by looking for the phrase "no tests ran" in the
output -- but **two of the files it runs discuss unittest's "NO TESTS
RAN" exit code in their docstrings**, so the phrase appeared in the
output of a run that collected 204 tests.  Empty collection is now read
**structurally**, from the runner's own summary line.

The targeted subset is the one that can catch a NEW unguarded read,
because every new read of a coordinator artifact is in one of those
files.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = REPO_ROOT / "components" / "northstar-agent-runtime"
RUNTIME_TESTS = RUNTIME_DIR / "tests"
REPO_TESTS = REPO_ROOT / "tests"

#: The coordinator's directory.  On a GitHub runner this does not exist
#: at all; on the coordinator's machine it holds every artifact the
#: B173 checks read.
COORDINATOR_DIR = Path("/home/muse-newapi")

#: The prefix of an artifact path under the coordinator's directory.
COORDINATOR_PREFIX = str(COORDINATOR_DIR)

#: A test file that reads an artifact outside the repository.
_COORDINATOR_REF = re.compile(
    r"""["']""" + re.escape(COORDINATOR_PREFIX) + r"""[^"']*["']"""
)

#: The artifacts that are MEASUREMENTS, and the checkout-local copy of
#: each.  A copy of a measurement of a named tree is still a true claim.
COPYABLE_MEASUREMENTS = {
    "census-parallel-corrected.txt": "docs/baseline/mutant-census/census-parallel-corrected.txt",
    "census-parallel.txt": "docs/baseline/mutant-census/census-parallel.txt",
    "census-v3.txt": "docs/baseline/mutant-census/census-v3.txt",
    "k3-remeasure.txt": "docs/baseline/mutant-census/k3-remeasure.txt",
    "k3-blind-rows.txt": "docs/baseline/mutant-census/k3-blind-rows.txt",
    "k3-bash-pins.txt": "docs/baseline/mutant-census/k3-bash-pins.txt",
}

#: The test files whose ONLY external artifact is a copyable MEASUREMENT.
#:
#: There are two kinds of artifact the coordinator holds, and they are
#: not treated the same way:
#:
#: * a **measurement of a named tree** -- the census files and the
#:   re-measurements.  The repository holds a copy of every one of them
#:   under ``docs/baseline/mutant-census/``, so the checks that read
#:   them **RUN** on a runner.  These files must not skip: a skip means
#:   a copy went missing and the check silently stopped checking.
#:
#: * a **live tool or live state** -- the referee ``b173-accept.sh``,
#:   the mutant probe ``b173-mutant.sh``, the watch script, the
#:   taskbooks, the slice manifests, the session JSONLs.  These change,
#:   and a copy of a moving target is not evidence.  A check that needs
#:   one SKIPS on a runner, and that is the honest answer -- there is
#:   nothing to copy.
#:
#: So the rule is not "no test may skip" -- that would be false, and a
#: check that cannot be satisfied gets disabled, which is worse.  The
#: rule is "**a check whose artifact is a measurement must RUN**".
MEASUREMENT_ONLY_FILES = frozenset({
    "test_equivalence_table_coverage.py",
    "test_unittest_blind_slices.py",
    "test_census_table_freshness.py",
})
_SIMULATION = '''\
"""Simulate a GitHub runner: the coordinator's directory is not there."""
import builtins
import os
import os.path as _osp
from pathlib import Path

REPO = str(Path({repo!r}).resolve())
COORD = {coord!r}

# The PYTHON INSTALLATION and pip's cache live under the coordinator's
# directory on the coordinator's machine.  On a runner they are at /usr
# and ~/.cache, so they must stay VISIBLE here too -- hiding them
# breaks the test RUNNER itself and produces failures that are the
# simulation's fault, not the tree's.
VISIBLE_PREFIXES = (
    REPO,
    os.path.join(COORD, ".local"),
    os.path.join(COORD, ".venv"),
    os.path.join(COORD, ".cache"),
    os.path.join(COORD, ".config"),
)


def _outside(p) -> bool:
    try:
        raw = os.fspath(p)
    except Exception:
        return False
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        s = os.path.abspath(raw)
    except Exception:
        return False
    if any(s.startswith(v) for v in VISIBLE_PREFIXES):
        return False
    return s.startswith(COORD)


def _is_coord_dir(p) -> bool:
    try:
        raw = os.fspath(p)
    except Exception:
        return False
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        return os.path.abspath(raw) == COORD
    except Exception:
        return False


_real_exists = Path.exists
_real_is_file = Path.is_file
_real_is_dir = Path.is_dir
_real_path_open = Path.open
_real_open = builtins.open
_real_scandir = os.scandir
_real_listdir = os.listdir
_real_osp_exists = _osp.exists


def exists(self):
    if _outside(self):
        return False
    return _real_exists(self)


def is_file(self):
    if _outside(self):
        return False
    return _real_is_file(self)


def is_dir(self):
    if _outside(self):
        return False
    return _real_is_dir(self)


def path_open(self, *a, **k):
    if _outside(self):
        raise FileNotFoundError(2, "No such file or directory", str(self))
    return _real_path_open(self, *a, **k)


def builtin_open(file, *a, **k):
    if isinstance(file, (str, bytes, os.PathLike)) and _outside(file):
        raise FileNotFoundError(2, "No such file or directory", str(file))
    return _real_open(file, *a, **k)


class _EmptyScandir:
    def __iter__(self):
        return iter(())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        return None


def scandir(p="."):
    if _is_coord_dir(p):
        return _EmptyScandir()
    return _real_scandir(p)


def listdir(p="."):
    if _is_coord_dir(p):
        return []
    return _real_listdir(p)


def osp_exists(p):
    if isinstance(p, (str, bytes, os.PathLike)) and _outside(p):
        return False
    return _real_osp_exists(p)


Path.exists = exists
Path.is_file = is_file
Path.is_dir = is_dir
Path.open = path_open
builtins.open = builtin_open
os.scandir = scandir
os.listdir = listdir
_osp.exists = osp_exists
os.path.exists = osp_exists
'''


def _coordinator_reading_files() -> list[Path]:
    """The test files that name the coordinator's directory.

    Both suites are covered: the repository's ``documentation`` job runs
    ``python -m unittest discover -s tests`` over ``tests/``, and the
    component's ``agent-runtime`` job runs ``pytest -q tests`` over
    ``components/northstar-agent-runtime/tests/``.  A file in either
    place can read a coordinator artifact, and a failure in either
    place is a red CI run.

    This file names the coordinator's directory too -- it has to, to
    name it -- so it **excludes itself**.  Otherwise the run below
    would execute this file, which would execute this file, and so on.
    """
    out = []
    for directory in (REPO_TESTS, RUNTIME_TESTS):
        for path in sorted(directory.glob("test_*.py")):
            if path.resolve() == Path(__file__).resolve():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if _COORDINATOR_REF.search(text):
                out.append(path)
    return out


class CoordinatorArtifactTests(unittest.TestCase):
    """The artifacts the B173 checks read must be reachable, or skipped."""

    def test_the_suite_has_files_that_read_the_coordinators_directory(self):
        """The guard is not vacuous.

        If no test read the coordinator's directory, the simulation
        below would prove nothing, and the rule would be untested.
        """
        files = _coordinator_reading_files()
        self.assertTrue(
            files,
            "no component test names the coordinator's directory, so the "
            "simulation cannot prove anything; this guard has gone stale",
        )

    def test_the_census_artifacts_have_a_checkout_local_copy(self):
        """The census artifacts are the ones the checks compare against.

        A copy under ``docs/baseline/mutant-census/`` is what lets the
        guard RUN on a runner -- a skip would leave the check unrun on
        CI, which is how the gap survived in the first place.
        """
        local = REPO_ROOT / "docs" / "baseline" / "mutant-census"
        for name in (
            "census-parallel-corrected.txt",
            "census-parallel.txt",
            "census-v3.txt",
        ):
            self.assertTrue(
                (local / name).is_file(),
                f"missing checkout-local census artifact: {local / name}",
            )

    def test_the_remeasurement_artifacts_have_a_checkout_local_copy(self):
        """Same, for the k/3 re-measurements."""
        local = REPO_ROOT / "docs" / "baseline" / "mutant-census"
        for name in ("k3-remeasure.txt", "k3-blind-rows.txt", "k3-bash-pins.txt"):
            self.assertTrue(
                (local / name).is_file(),
                f"missing checkout-local re-measurement: {local / name}",
            )


class CoordinatorArtifactSimulationTests(unittest.TestCase):
    """The files that read the coordinator's directory must not FAIL."""

    def setUp(self):
        if not RUNTIME_DIR.is_dir():
            self.skipTest(f"runtime component missing: {RUNTIME_DIR}")
        self.files = _coordinator_reading_files()
        if not self.files:
            self.skipTest("no component test names the coordinator's directory")

    def _run_group(self, directory, group, sim):
        """Run one group under a runner that is always present.

        Returns ``(status, output)`` where status is one of:

        ``"ran"``
            the runner ran and collected tests; the output carries the
            count, so a group that collected tests but all of them
            **skipped** is distinguishable from one that really ran them;
        ``"no-runner"``
            the runner could not be started at all -- a broken
            installation, not a missing one (see below);
        ``"empty"``
            the runner ran but collected **no** tests -- a measurement
            that did not happen.

        The **runner is part of the measurement**, and so is **which
        runner CI uses**.

        CI runs the component suite with ``pytest -q tests`` and the
        repository suite with ``python -m unittest discover -s tests``.
        The two runners do not collect the same tests across a suite:
        pytest also collects the standalone module-level ``test_*``
        functions that unittest's loader never sees.

        But the guard itself lives in the repository's suite, which the
        ``documentation`` job runs -- and that job installs **no
        dependencies**, so ``pytest`` does not exist there.  A guard
        that needs pytest is a guard that does not run on the job that
        runs it.  And a group run with a missing runner exits non-zero
        with a traceback that carries **no** ``FAILED`` line -- so the
        "no failures" assertion would pass on a run that collected
        **nothing at all**.  A guard that passes because it measured
        nothing is worse than no guard: it reports coverage that does
        not exist.

        The resolution is measured, not assumed: **all 23** files that
        read the coordinator's directory are ``TestCase``-based, with
        **zero** standalone module-level test functions (verified by AST
        over all 23), so unittest's loader collects exactly the same
        tests pytest does.  So the guard runs **unittest**, which is in
        the standard library and therefore present in every job.

        Running it under unittest also removes the last way the guard
        could pass vacuously: a missing runner is no longer a thing
        that can happen, so "no group ran" can only mean the guard
        itself is broken.
        """
        # unittest, for BOTH groups: it is the only runner present in
        # every CI job, and it collects the same tests in these files.
        command = [
            sys.executable, "-m", "unittest", "-v",
            *[Path(f).stem for f in group],
        ]
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(REPO_ROOT), str(RUNTIME_DIR), str(RUNTIME_TESTS), str(directory), str(sim)]
        )
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            proc = subprocess.run(
                command,
                cwd=str(directory),
                env=env,
                capture_output=True,
                text=True,
                timeout=1800,
            )
        except OSError as error:
            return "no-runner", str(error)
        out = proc.stdout + proc.stderr
        if "No module named pytest" in out or "No module named unittest" in out:
            return "no-runner", out
        # "the runner collected nothing" is read STRUCTURALLY, from the
        # runner's own summary line -- not from a substring.  The
        # phrase "no tests ran" appears in the DOCSTRINGS of two of the
        # files this guard runs (test_judge_hygiene.py and
        # test_unittest_blind_slices.py both talk about unittest's
        # "NO TESTS RAN" exit code), so a substring check reports an
        # empty collection when the collection was 204 tests long.
        if re.search(r"^Ran 0 tests?\b", out, re.MULTILINE):
            return "empty", out
        if re.search(r"collected 0 items?\b", out):
            return "empty", out
        return "ran", out

    def _counts(self, out):
        """``(passed, skipped)`` -- the tests that passed, and those that skipped.

        A **skip** is not a pass.  The whole point of the checkout-local
        copies is that the checks RUN on a runner; a run in which every
        check skipped is the gap reappearing in a new shape, and a guard
        that reports it as a pass hides it again.

        The two runners print their counts differently, so both are read:

        * pytest prints ``9 passed`` / ``3 passed, 6 skipped``;
        * unittest prints ``Ran 6 tests`` with ``OK (skipped=6)`` -- and
          there the "Ran" count is every test it collected, **passed and
          skipped alike**, so the skipped ones have to be subtracted.

        Counting "Ran 6" as six passes is exactly the mistake this check
        exists to catch: it would report six tests as having checked
        something when all six skipped.
        """
        pytest_passed = pytest_skipped = 0
        # pytest: "9 passed, 6 skipped, 1501 subtests passed"
        for count, kind in re.findall(r"(\d+) (passed|skipped)\b", out):
            if kind == "passed":
                pytest_passed += int(count)
            else:
                pytest_skipped += int(count)
        # unittest: "Ran 6 tests in 0.010s" and "OK (skipped=6)"
        unittest_total = 0
        match = re.search(r"^Ran (\d+) tests?", out, re.MULTILINE)
        if match:
            unittest_total = int(match.group(1))
        unittest_skipped = 0
        match = re.search(r"skipped=(\d+)", out)
        if match:
            unittest_skipped = int(match.group(1))
        if unittest_total:
            # The unittest count is authoritative for the repository
            # group: "Ran N" is every collected test, so the ones that
            # skipped are subtracted to get the ones that passed.
            return unittest_total - unittest_skipped, unittest_skipped
        return pytest_passed, pytest_skipped

    def _skipped_tests(self, out):
        """The tests that SKIPPED, as ``"<module>:<test>"`` strings.

        unittest ``-v`` prints the test id on one line and the
        **docstring and the skip marker on the NEXT**::

            test_a_row (test_mod.Class.test_a_row)
            A weak row must be one the measurement says is weak. ... skipped 'why'

        So the id has to be carried forward from the previous line --
        matching ``... skipped`` on the same line as the id finds
        nothing at all.  (That was the first version, and it found
        nothing.)

        The module is what matters here: the guard asks "did a check in
        one of the measurement-backed files skip", and the module is what
        identifies the file.
        """
        names = []
        current = None
        current_module = None
        for line in out.splitlines():
            match = re.match(r"^(\S+) \(([^)]+)\)\s*$", line)
            if match:
                # "test_name (module.Class.test_name)"
                current = match.group(1)
                current_module = match.group(2).split(".")[0]
                continue
            if "... skipped" in line and current:
                names.append(f"{current_module}:{current}")
        return names

    def _skipped_in_measurement_files(self, out, group):
        """The skips that happened in the files whose artifact is a copy.

        A file whose ONLY external artifact is a copyable MEASUREMENT
        must not skip on a runner: the copy is in the repository, so a
        skip means the check is not running, which is the gap this guard
        exists to close.

        The two runners name the file differently -- pytest names the
        FILE (``test_x.py``) and unittest names the MODULE
        (``test_x``) -- so both are reduced to the stem before they are
        compared.
        """
        measurement_stems = {
            Path(f).stem for f in group if Path(f).name in MEASUREMENT_ONLY_FILES
        }
        if not measurement_stems:
            return []
        skipped = []
        for name in self._skipped_tests(out):
            stem = name.split("::")[0].split(":")[0]
            if Path(stem).stem in measurement_stems:
                skipped.append(name)
        return skipped

    def test_the_files_that_read_the_coordinator_survive_its_absence(self):
        """Run them with the coordinator's directory simulated as absent.

        Every one of them must PASS or SKIP.  A FAILURE is the defect
        this file exists for.

        The files are run from the directory they live in, because the
        two suites are run from different working directories by CI
        (the component job's ``working-directory`` is the component; the
        documentation job's is the repository root), and a test that
        depends on its working directory would behave differently.
        """
        failures = []
        ran = []
        empty = []
        all_skipped = []
        unexpected_skips = []
        no_runner = []
        with tempfile.TemporaryDirectory(prefix="b173-ci-sim-") as tmp:
            sim = Path(tmp)
            (sim / "sitecustomize.py").write_text(
                _SIMULATION.format(repo=str(REPO_ROOT), coord=COORDINATOR_PREFIX),
                encoding="utf-8",
            )
            for directory in {f.parent for f in self.files}:
                group = [str(f) for f in self.files if f.parent == directory]
                status, out = self._run_group(directory, group, sim)
                if status == "no-runner":
                    # The runner this suite's CI job uses is not
                    # installed here.  That is a fact about this
                    # machine, not about the tree -- it is reported and
                    # the group is skipped, never counted as a pass.
                    no_runner.append(f"{directory.name}/the runner is not installed")
                    continue
                if status == "empty":
                    empty.append(f"{directory.name}/the runner collected no tests")
                    continue
                ran.append(f"{directory.name}/{len(group)} file(s)")
                passed, skipped = self._counts(out)
                if passed == 0 and skipped > 0:
                    all_skipped.append(
                        f"{directory.name}/every one of the {skipped} test(s) "
                        "skipped, so nothing was actually checked"
                    )
                # A skip leaves the check UNRUN.  The checkout-local
                # copies are what make the measurement-backed checks RUN
                # on a runner -- so a skip in one of THOSE files means a
                # copy went missing, and it is a defect.  A skip in a
                # file whose artifact is the coordinator's live state is
                # the honest answer and is not a defect.
                for name in self._skipped_in_measurement_files(out, group):
                    unexpected_skips.append(
                        f"{directory.name}/{name} skipped, but its artifact "
                        "is a measurement with a checkout-local copy, so the "
                        "check should have run"
                    )
                failures.extend(
                    f"{directory.name}/{line}"
                    for line in out.splitlines()
                    if line.startswith(("FAILED", "SUBFAILED", "ERROR"))
                )
        self.assertEqual(
            failures, [],
            "these tests FAIL when the coordinator's directory is absent, "
            "which is every CI run:\n" + "\n".join(failures),
        )
        self.assertEqual(
            empty, [],
            "the runner ran but collected no tests, so the simulation "
            "measured nothing:\n" + "\n".join(empty),
        )
        self.assertEqual(
            all_skipped, [],
            "every test in a group skipped, so the simulation proved "
            "nothing -- the checks must RUN on a runner:\n"
            + "\n".join(all_skipped),
        )
        self.assertEqual(
            unexpected_skips, [],
            "these checks SKIPPED on a runner, so they did not run at all:\n"
            + "\n".join(unexpected_skips),
        )
        self.assertTrue(
            ran,
            "no group of tests was actually run, so the simulation proved "
            "nothing; the guard is not measuring anything"
            + (
                "\nthese groups could not run at all:\n  "
                + "\n  ".join(no_runner)
                if no_runner
                else ""
            ),
        )


if __name__ == "__main__":
    unittest.main()
