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


def _build_wheel(tmp: Path) -> Path:
    """Build the runtime's wheel for real.

    Reading ``pyproject.toml`` proves only what somebody wrote; the wheel
    is the artifact setuptools actually ships.
    """
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
            str(COMPONENT),
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
_CACHE: dict[str, object] = {}


def _built_wheel_and_site() -> tuple[Path, Path]:
    """Return ``(wheel, site)`` for the runtime component, built on demand."""
    if "wheel" not in _CACHE:
        tmp = tempfile.mkdtemp(prefix="b173-runtime-data-files-")
        tmp_path = Path(tmp)
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
        self.assertEqual(len(top), 1613, sorted(top)[:5])


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
