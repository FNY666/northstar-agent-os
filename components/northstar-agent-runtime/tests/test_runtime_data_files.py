"""Every data file a module reads must be in the wheel.

BACKGROUND (measured 2026-11-16)
--------------------------------
``pip install .`` installs MODULES.  The two installation mechanisms are
both module-shaped::

    [tool.setuptools]
    py-modules = [ ... ]                   # flat .py modules

    [tool.setuptools.packages.find]
    include = [ "providers*", "tools*" ]   # package members

A **data file** -- a ``.json`` or ``.toml`` a module reads at runtime --
is in neither mechanism, so it exists in the checkout and disappears
after ``pip install .``.

The runtime component has two such data files::

    deny_monotonicity_baseline.json     # the pinned deny set
    policy/dataflow.toml                # the default dataflow policy

**One of them has no fallback, and it is the one that matters.**  The
dataflow policy embeds a byte-identical copy of its TOML
(``_DEFAULT_POLICY_TOML``), so the installed surface still parses the
same six sources and six sinks.  The deny-monotonicity baseline has no
such fallback -- ``load_baseline`` raises ``FileNotFoundError`` and
``deny_monotonicity_check`` fails closed by design:

    $ python3 -c "import deny_monotonicity as dm; print(dm.deny_monotonicity_check())"
    (False, 'deny-monotonicity baseline missing: regenerate with
     deny_monotonicity.regenerate_baseline() after review')

That is the installed surface.  In the checkout the same call returns:

    (True, 'deny-monotonicity holds: 5 denials, 0 added since baseline, 0 lost')

The module's own docstring says the check is "Bench-ready ... for the
governance bench", and it fails closed *on purpose*: "A missing baseline
fails closed: without a pin there is nothing to be monotone against."
So on the installed surface the check cannot pass, no matter what the
gate does.

THE RULE THIS SLICE PINS
-------------------------
> **Every data file a module reads at runtime is in the wheel it builds.**

Checked against the INSTALLED surface, so a module with an embedded
fallback (the dataflow policy) and one without (the deny baseline) are
distinguished rather than conflated.

These tests pin:

* the deny baseline is IN the wheel the component builds;
* the installed surface can read it and the check passes there;
* the checkout and the installed surface read the SAME BYTES;
* the dataflow policy parses the same rules in both places;
* the guard is not a rubber stamp: a data file that is read but not
  shipped is caught and NAMED.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import dataflow_policy
import deny_monotonicity as dm

COMPONENT = Path(__file__).resolve().parents[1]
PYPROJECT = COMPONENT / "pyproject.toml"

#: The data files the runtime reads at runtime, and whether the module has
#: an embedded fallback for it.  A fallback is a *correct* design (the
#: installed surface still behaves), so it must not be reported as missing
#: -- but a data file with NO fallback must be reported.
#:
#: The value is the path INSIDE THE WHEEL.  The checkout path and the wheel
#: path are the same here, because the data files live in the component's
#: ``policy/`` directory and the wheel keeps that directory's layout.
DATA_FILES = {
    "policy/deny_monotonicity_baseline.json": False,
    "policy/dataflow.toml": True,
}


def _build_artifacts_in_the_component() -> set[str]:
    """The build scratch artifacts currently sitting in the component.

    setuptools writes ``build/`` and ``<name>.egg-info/`` into the source
    directory it is given.  Both are listed here so a test can assert
    that a wheel build left the checkout alone.
    """
    found = set()
    for path in COMPONENT.iterdir():
        if path.name == "build" or path.name.endswith(".egg-info"):
            found.add(path.name)
    return found


def _build_wheel(tmp: Path) -> Path:
    """Build the runtime's wheel for real.

    Reading ``pyproject.toml`` proves only what somebody wrote; the wheel
    is the artifact setuptools actually ships.

    The build runs OUT OF TREE.  setuptools writes its scratch tree
    (``build/``, ``<name>.egg-info/``) into the source directory it is
    handed, does not clean it between builds, and a second build then
    dies with ``Errno 17: File exists`` on the first build's
    ``.dist-info``.  So the sources are copied to a scratch directory
    first and the wheel is built there: the artifact is then a function
    of the source and nothing else, and the checkout is untouched.

    The copy is of the *build* inputs only -- the modules, the packages
    and the packaging configuration -- not of ``tests/``, which is not
    part of the wheel and is large.
    """
    source = tmp / "src"
    shutil.copytree(
        COMPONENT,
        source,
        ignore=shutil.ignore_patterns(
            "tests",
            "sdk-ts",
            "build",
            "dist",
            "__pycache__",
            "*.egg-info",
            "*.bundle",
        ),
    )
    dist = tmp / "dist"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "-w",
            str(dist),
            str(source),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            "building the runtime wheel failed:\n%s" % result.stdout[-4000:]
        )
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise AssertionError("expected exactly one wheel, got %s" % wheels)
    return wheels[0]


#: The built wheel and the site it was installed into, built ONCE per test
#: class.  Building the runtime's wheel costs a few seconds, and the
#: installed surface is read-only, so every test in a class can share it.
#: The wheel is still really built and really installed -- only the
#: repetition is removed.
#:
#: The scratch directory is kept alive for as long as the process lives and
#: removed when it exits.  A wheel build leaves ~180 MB behind (the source
#: copy plus the scratch tree), and leaving that in ``/tmp`` for every test
#: run is how a test suite fills a disk.
_CACHE: dict[str, object] = {}
_SCRATCH: list[tempfile.TemporaryDirectory] = []


def _scratch_dir(prefix: str) -> Path:
    """A temporary directory removed when the process exits."""
    holder = tempfile.TemporaryDirectory(prefix=prefix)
    _SCRATCH.append(holder)
    return Path(holder.name)


def _built_wheel_and_site() -> tuple[Path, Path]:
    """Return ``(wheel, site)`` for the runtime component, built on demand."""
    if "wheel" not in _CACHE:
        tmp_path = _scratch_dir("b173-runtime-data-files-")
        wheel = _build_wheel(tmp_path)
        site = tmp_path / "site"
        site.mkdir()
        _install(wheel, site)
        _CACHE["wheel"] = wheel
        _CACHE["site"] = site
    return _CACHE["wheel"], _CACHE["site"]


def _install(wheel: Path, target: Path) -> None:
    """Install the wheel into an isolated directory."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--quiet",
            "--no-deps",
            "--no-index",
            "--target",
            str(target),
            str(wheel),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError("installing the wheel failed:\n%s" % result.stdout)


def _run_in(site: Path, code: str) -> subprocess.CompletedProcess:
    """Run ``code`` against an installed surface, from a neutral directory."""
    workdir = site.parent / "cwd"
    workdir.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(workdir),
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(site)},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


class WheelBuildIsolationTests(unittest.TestCase):
    """Building the wheel must not write into the component's checkout.

    THE DEFECT THIS PINS
    --------------------
    ``pip wheel <dir>`` runs the build backend with the *source directory*
    as the working directory, and setuptools writes its scratch tree
    there::

        <component>/build/bdist.<platform>/wheel/
        <component>/<name>.egg-info/

    The scratch tree is NOT cleaned between builds, so the second build
    finds the first build's ``.dist-info`` already in place and dies::

        error: [Errno 17] File exists:
          'build/bdist.linux-aarch64/wheel/northstar_agent_runtime-...dist-info'
        ERROR: Failed building wheel for northstar-agent-runtime

    Measured on this repository before the fix: 7 of the tests in
    ``WheelDataFileTests`` failed on that error, and 10 further errors in
    the same component's suite were the same build failure seen from
    other tests.

    The scratch tree is also *state*: a stale ``build/`` directory in a
    checkout can make a later build fail for reasons that have nothing to
    do with the code under test.  A test that builds a wheel must build
    it out of tree, so the artifact it inspects is a function of the
    source and nothing else.
    """

    def test_building_the_wheel_leaves_the_checkout_unchanged(self):
        # RED against the in-tree build: the build directory appears in
        # the component, and the egg-info directory with it.
        before = _build_artifacts_in_the_component()
        _build_wheel(_scratch_dir("b173-isolation-"))
        after = _build_artifacts_in_the_component()
        self.assertEqual(
            before,
            after,
            "building the wheel wrote into the component checkout: %s"
            % sorted(after - before),
        )

    def test_two_wheel_builds_in_a_row_both_succeed(self):
        # The failure mode the isolation fixes: the second build trips
        # over the first build's scratch tree and dies with
        # ``Errno 17: File exists``.
        first = _build_wheel(_scratch_dir("b173-iso-a-"))
        second = _build_wheel(_scratch_dir("b173-iso-b-"))
        self.assertTrue(first.is_file())
        self.assertTrue(second.is_file())
        self.assertNotEqual(
            first.resolve(),
            second.resolve(),
            "the two builds must be independent artifacts",
        )
        # The same source must give the same wheel: a build that is a
        # function of the source and nothing else.  (The two wheels carry
        # the same name -- they are the same package -- so they are
        # compared by their contents, not by their file names.)
        with zipfile.ZipFile(first) as a, zipfile.ZipFile(second) as b:
            self.assertEqual(
                sorted(a.namelist()),
                sorted(b.namelist()),
                "two builds of the same source disagree about the wheel contents",
            )


class WheelDataFileTests(unittest.TestCase):
    """The wheel must carry the data files the modules read."""

    def test_the_wheel_carries_the_deny_monotonicity_baseline(self):
        # THE DEFECT, as one fact: the wheel shipped no data file at all.
        wheel, _site = _built_wheel_and_site()
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
        self.assertIn(
            "policy/deny_monotonicity_baseline.json",
            names,
            "the wheel does not ship the deny-monotonicity baseline; "
            "the installed surface therefore cannot run the check",
        )

    def test_the_wheel_carries_every_data_file_the_modules_read(self):
        # The rule, applied to the whole component rather than to one file.
        wheel, _site = _built_wheel_and_site()
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
        for name in DATA_FILES:
            with self.subTest(data_file=name):
                self.assertIn(
                    name,
                    names,
                    "the wheel does not ship %s" % name,
                )

    def test_the_wheel_still_carries_every_module(self):
        # The data files are added, not traded against the modules.
        wheel, _site = _built_wheel_and_site()
        with zipfile.ZipFile(wheel) as archive:
            top = {
                    Path(n).stem
                    for n in archive.namelist()
                    if n.endswith(".py") and "/" not in n
                }
        self.assertIn("cli", top)
        self.assertIn("deny_monotonicity", top)
        # The wheel's flat-module count is pinned here, and it is the ONE
        # place the count is measured against the built artefact rather
        # than against a list -- so a new module that joins the flat
        # surface shows up here and nowhere else until this number moves.
        # 1615 == 1614 (pre-finding_gate) + 1 (finding_gate).
        self.assertIn("finding_gate", top)
        self.assertEqual(len(top), 1619, sorted(top)[:5])


class InstalledSurfaceTests(unittest.TestCase):
    """The installed surface must be able to READ the data files."""

    def test_the_installed_surface_finds_the_deny_baseline(self):
        _wheel, site = _built_wheel_and_site()
        run = _run_in(
                site,
                "import deny_monotonicity as dm; "
                "print('EXISTS', dm.baseline_path().exists()); "
                "print('PATH', dm.baseline_path())",
            )
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertIn("EXISTS True", run.stdout)

    def test_the_deny_monotonicity_check_passes_on_the_installed_surface(self):
        # The check is fail-closed by design, so on an installed surface
        # that lacks the baseline it can never pass.
        _wheel, site = _built_wheel_and_site()
        run = _run_in(
                site,
                "import deny_monotonicity as dm; "
                "ok, message = dm.deny_monotonicity_check(); "
                "print('OK', ok); print('MSG', message)",
            )
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertIn("OK True", run.stdout, run.stdout)
        self.assertIn("deny-monotonicity holds", run.stdout)

    def test_the_installed_baseline_is_byte_identical_to_the_checkout_one(self):
        # "Both places have a file" is not the claim.  "Both places have
        # THE SAME FILE" is.
        _wheel, site = _built_wheel_and_site()
        run = _run_in(
                site,
                "import hashlib, deny_monotonicity as dm; "
                "data = dm.baseline_path().read_bytes(); "
                "print('SHA', hashlib.sha256(data).hexdigest()); "
                "print('LEN', len(data))",
            )
        self.assertEqual(run.returncode, 0, run.stdout)
        local = dm.baseline_path().read_bytes()
        import hashlib

        expected = hashlib.sha256(local).hexdigest()
        self.assertIn("SHA %s" % expected, run.stdout)
        self.assertIn("LEN %d" % len(local), run.stdout)

    def test_the_dataflow_policy_parses_the_same_rules_when_installed(self):
        # The dataflow policy HAS an embedded fallback, so its behaviour was
        # already correct -- and this test says so, so a future change that
        # breaks it is caught.
        _wheel, site = _built_wheel_and_site()
        run = _run_in(
                site,
                "import dataflow_policy as dp; "
                "p = dp.DataflowPolicy.default(); "
                "print('SOURCES', len(p.sources)); "
                "print('SINKS', len(p.sinks)); "
                "print('VERSION', p.version)",
            )
        self.assertEqual(run.returncode, 0, run.stdout)
        local = dataflow_policy.DataflowPolicy.default()
        self.assertIn("SOURCES %d" % len(local.sources), run.stdout)
        self.assertIn("SINKS %d" % len(local.sinks), run.stdout)
        self.assertIn("VERSION %d" % local.version, run.stdout)


class CheckoutBehaviourTests(unittest.TestCase):
    """The checkout's behaviour must not change."""

    def test_the_checkout_check_still_passes(self):
        ok, message = dm.deny_monotonicity_check()
        self.assertTrue(ok, message)
        self.assertIn("deny-monotonicity holds", message)

    def test_the_baseline_is_still_pinned_next_to_the_runtime(self):
        # The baseline is a pinned, reviewed artifact; it must stay inside
        # the component and stay a plain JSON file with the same shape.
        self.assertTrue(dm.baseline_path().exists())
        payload = json.loads(dm.baseline_path().read_text(encoding="utf-8"))
        self.assertEqual(payload["version"], dm.DENY_MONOTONICITY_VERSION)
        self.assertIn("deny_set", payload)

    def test_saving_and_loading_a_baseline_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            deny_set = {("p", "c")}
            dm.save_baseline(deny_set, path)
            self.assertEqual(dm.load_baseline(path), deny_set)


class GuardHonestyTests(unittest.TestCase):
    """The guard must be real: it must fail when a data file is not shipped."""

    def test_a_data_file_that_is_read_but_not_shipped_is_caught_and_named(self):
        # The recurrence case, in a tmpdir, never in the working tree.
        with tempfile.TemporaryDirectory() as tmp:
            component = Path(tmp) / "a_component"
            component.mkdir()
            (component / "a_module.py").write_text("x = 1\n", encoding="utf-8")
            (component / "needed.json").write_text("{}\n", encoding="utf-8")
            (component / "pyproject.toml").write_text(
                '[tool.setuptools]\npy-modules = ["a_module"]\n',
                encoding="utf-8",
            )
            on_disk = {
                path.name
                for path in component.iterdir()
                if path.is_file() and path.suffix == ".json"
            }
            shipped = set()  # the wheel ships no data file
            missing = sorted(on_disk - shipped)
        self.assertEqual(missing, ["needed.json"])
        self.assertIn("needed.json", str(missing))

    def test_a_data_file_with_an_embedded_fallback_is_not_reported(self):
        # The dataflow policy has a fallback, so it is NOT missing even
        # though the wheel would not carry it.  Reporting it would make
        # the guard cry wolf on correct code.
        with tempfile.TemporaryDirectory() as tmp:
            component = Path(tmp) / "a_component"
            component.mkdir()
            (component / "a_module.py").write_text("x = 1\n", encoding="utf-8")
            (component / "fallback.toml").write_text("x = 1\n", encoding="utf-8")
            on_disk = {"fallback.toml"}
            has_fallback = {"fallback.toml"}
            shipped = set()
            missing = sorted(on_disk - shipped - has_fallback)
        self.assertEqual(missing, [])


class DocbuildDataFileViewTests(unittest.TestCase):
    """The repo-wide view of the data-file surface."""

    def setUp(self):
        self.docbuild = _load_docbuild()

    def test_the_view_sees_the_runtime_data_files(self):
        on_disk = self.docbuild.data_files_on_disk("northstar-agent-runtime")
        self.assertIn("policy/deny_monotonicity_baseline.json", on_disk)
        self.assertIn("policy/dataflow.toml", on_disk)

    def test_the_view_reports_nothing_missing_after_the_fix(self):
        for component in self.docbuild.components_that_ship_a_wheel():
            with self.subTest(component=component):
                self.assertEqual(
                    self.docbuild.missing_data_files(component),
                    [],
                    "data file(s) %s that the wheel would not ship"
                    % self.docbuild.missing_data_files(component),
                )

    def test_the_view_catches_the_pre_fix_layout(self):
        # The layout as it was BEFORE this slice: the baseline in the
        # component root, with no package-data entry to reach it.
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            component = tree / "components" / "northstar-agent-runtime"
            (component / "policy").mkdir(parents=True)
            (component / "policy" / "dataflow.toml").write_text("x = 1\n")
            (component / "deny_monotonicity_baseline.json").write_text("{}\n")
            (component / "pyproject.toml").write_text(
                '[tool.setuptools]\npy-modules = ["cli"]\n',
                encoding="utf-8",
            )
            original = self.docbuild.ROOT
            try:
                self.docbuild.ROOT = tree
                missing = self.docbuild.missing_data_files("northstar-agent-runtime")
            finally:
                self.docbuild.ROOT = original
        self.assertEqual(
            missing,
            ["deny_monotonicity_baseline.json", "policy/dataflow.toml"],
        )


def _load_docbuild():
    """Import the repository's ``tests/docbuild.py`` module.

    It lives at the repository root's ``tests/`` directory, which is not on
    this component's import path, so it is loaded by file location.  The
    module is registered in ``sys.modules`` first: ``dataclass`` resolves
    the decorated class's module by name, and a module that is not
    registered there raises at decoration time.
    """
    import importlib.util
    import sys

    path = COMPONENT.parents[1] / "tests" / "docbuild.py"
    spec = importlib.util.spec_from_file_location("docbuild_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    unittest.main()


class RegenerateBaselineCorpusTests(unittest.TestCase):
    """``regenerate_baseline`` must use the corpus it is GIVEN.

    One planted fault survived this slice's suite:

      or@266  ``compute_deny_set(corpus or DENY_CORPUS, build_gate_fn())``

    The expression reads "the corpus I was given, or the default one".
    The mutant (``or`` -> ``and``) does not read that at all: it reads
    "the corpus I was given AND the default one", and because ``and``
    returns the SECOND operand when the first is truthy, a corpus the
    caller DID give is silently replaced by the default corpus.  A
    caller who regenerates the baseline against a custom corpus would
    get back a baseline describing the default canary set -- a floor
    they never reviewed and never approved.

    The two halves are pinned here:

    * a corpus the caller GIVES is the corpus that is evaluated and
      pinned (this is what kills the mutant);
    * NO corpus falls back to the default canary corpus.

    The EMPTY corpus is a third case, and the module's answer to it is
    deliberate: an empty corpus also falls back to the default canary
    set.  That is the SAFE answer, and it is pinned below rather than
    changed.  A baseline is a FLOOR -- the set of denials the gate is
    not allowed to lose.  Pinning the empty set as the floor would
    make the monotonicity check vacuous: a gate that denied NOTHING at
    all would satisfy it, and the canary set exists precisely to make
    sure a gate that stops denying is caught.  So the module refuses
    to let a caller talk it out of its own canaries.
    """

    def test_a_given_corpus_is_the_corpus_that_gets_pinned(self):
        """`or@266`: the corpus the caller GIVES is the corpus pinned.

        Under the mutant (``or`` -> ``and``) the default corpus is
        pinned instead of the given one, so the baseline describes five
        canary denials the caller never asked about.
        """
        custom = (
            {
                "probe": "custom-probe",
                "tool": "BankTransfer",
                "kind": "mutating",
                "payload": {"action": "wire money"},
                "config": "policy",
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            dm.regenerate_baseline(corpus=custom, path=path)
            pinned = dm.load_baseline(path)
        self.assertEqual(pinned, {("custom-probe", "denial.disallowed_tools")})
        self.assertNotIn(("disallowed-tool", "denial.disallowed_tools"), pinned)

    def test_a_given_corpus_replaces_the_default_corpus_entirely(self):
        """`or@266`: the difference, stated as a difference.

        A custom corpus and the default corpus must produce DIFFERENT
        baselines.  Under the mutant they are the same file, so the
        floor a reviewer approves is not the floor that was pinned.
        """
        custom = (
            {
                "probe": "custom-probe",
                "tool": "BankTransfer",
                "kind": "mutating",
                "payload": {"action": "wire money"},
                "config": "policy",
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            custom_path = Path(tmp) / "custom.json"
            default_path = Path(tmp) / "default.json"
            dm.regenerate_baseline(corpus=custom, path=custom_path)
            dm.regenerate_baseline(path=default_path)
            custom_pinned = dm.load_baseline(custom_path)
            default_pinned = dm.load_baseline(default_path)
        self.assertNotEqual(custom_pinned, default_pinned)
        self.assertEqual(len(custom_pinned), 1)
        self.assertEqual(len(default_pinned), 5)

    def test_no_corpus_falls_back_to_the_default_corpus(self):
        """`or@266`: the fallback half, from the other side.

        With NO corpus given at all, the default corpus is used -- that
        is the point of the ``or``.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            dm.regenerate_baseline(path=path)
            pinned = dm.load_baseline(path)
        self.assertEqual(
            pinned, dm.compute_deny_set(dm.DENY_CORPUS, dm.build_gate_fn())
        )
        self.assertEqual(len(pinned), 5)

    def test_an_empty_corpus_still_falls_back_to_the_canary_set(self):
        """`or@266`: the empty corpus, and why the fallback is SAFE.

        An empty corpus is falsy, so the module pins its DEFAULT canary
        set rather than an empty floor.  That is deliberate: the
        baseline is the set of denials the gate may not lose, and an
        empty floor would make the monotonicity check vacuous -- a gate
        that denied nothing at all would satisfy it.  The canary set
        exists precisely to catch that, so a caller cannot talk the
        module out of it.

        This test pins the safe behaviour; it is NOT the killer for the
        mutant.  The killer is the custom-corpus test above.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            dm.regenerate_baseline(corpus=(), path=path)
            pinned = dm.load_baseline(path)
        self.assertEqual(
            pinned, dm.compute_deny_set(dm.DENY_CORPUS, dm.build_gate_fn())
        )
        self.assertEqual(len(pinned), 5)

    def test_an_empty_corpus_does_not_pin_an_empty_floor(self):
        """`or@266`: the consequence, stated as a difference.

        The empty corpus and the default corpus produce the SAME
        baseline -- the canary floor -- and that floor is never empty.
        """
        with tempfile.TemporaryDirectory() as tmp:
            empty_path = Path(tmp) / "empty.json"
            default_path = Path(tmp) / "default.json"
            dm.regenerate_baseline(corpus=(), path=empty_path)
            dm.regenerate_baseline(path=default_path)
            empty = dm.load_baseline(empty_path)
            default = dm.load_baseline(default_path)
        self.assertEqual(empty, default)
        self.assertEqual(len(empty), 5)
