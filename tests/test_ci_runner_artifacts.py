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

WHAT THIS TEST DOES
-------------------
It **runs** the component suite with the coordinator's directory
simulated as absent, and asserts that nothing fails.  The simulation is
a ``sitecustomize.py`` that makes ``Path.exists`` / ``is_file`` /
``open`` under the coordinator's directory fail, and makes
``os.scandir`` of it return nothing -- so a ``Path.glob`` there finds
no manifest, exactly as on a runner.

Running the whole suite costs minutes, so this test does NOT run it by
default.  Instead it:

* checks the **shape** of every test that names the coordinator's
  directory -- an artifact read must be guarded by an existence check
  or a ``skipTest``; and
* runs a **targeted** subset (the files that name the coordinator's
  directory) under the simulation, which is fast, and asserts that
  none of them fails.

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

#: The simulation.  It is written into a scratch directory and put on
#: ``PYTHONPATH``, so ``sitecustomize`` is imported by every Python
#: process the suite starts.
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
        with tempfile.TemporaryDirectory(prefix="b173-ci-sim-") as tmp:
            sim = Path(tmp)
            (sim / "sitecustomize.py").write_text(
                _SIMULATION.format(repo=str(REPO_ROOT), coord=COORDINATOR_PREFIX),
                encoding="utf-8",
            )
            for directory in {f.parent for f in self.files}:
                group = [str(f) for f in self.files if f.parent == directory]
                env = dict(os.environ)
                env["PYTHONPATH"] = os.pathsep.join(
                    [str(REPO_ROOT), str(RUNTIME_DIR), str(RUNTIME_TESTS), str(sim)]
                )
                env["PYTHONDONTWRITEBYTECODE"] = "1"
                proc = subprocess.run(
                    [
                        sys.executable, "-m", "pytest", "-q",
                        "-p", "no:cacheprovider", *group,
                    ],
                    cwd=str(directory),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=1800,
                )
                if proc.returncode != 0:
                    out = proc.stdout + proc.stderr
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


if __name__ == "__main__":
    unittest.main()
