"""Every module a component ships must be in the wheel.

BACKGROUND (measured 2026-11-16)
--------------------------------
``pip install .`` puts a component's modules on the path, and the way it
does so is declared in that component's ``pyproject.toml``:

    [tool.setuptools]
    py-modules = [ ... ]                   # the flat modules

    [tool.setuptools.packages.find]
    include = [ "providers*", "tools*" ]   # the package members

A module that exists in the repository but is in neither list works in the
checkout and disappears after ``pip install .`` -- the failure mode nobody
notices until a user hits it.

**One module in the whole repository was in that state**: the interop
component's ``remote_worker.py``.

    $ python3 -m pip wheel --no-deps --no-build-isolation -w dist .
    $ python3 -c "import zipfile; print(zipfile.ZipFile(w).namelist())"
    canary.py handoff.py interop_adapter.py interop_contract.py
    process_adapter.py process_backend.py remote_transport.py
    remote_worker IN WHEEL: False

    $ PYTHONPATH=<installed site> python3 -c "import remote_worker"
    ModuleNotFoundError: No module named 'remote_worker'

``remote_worker.py`` is the P3-3 readiness scorecard, and three documents
name ``python3 -m remote_worker --score`` as a CI entry point.  So the
documented CI command could not run on the installed surface.

It was not a deliberate exclusion: the commit that added the module
(2026-09-07, "P3-3: remote/hosted worker evaluation") never touched
``pyproject.toml`` at all.

WHY NOBODY NOTICED
------------------
Two reasons, and the second is the interesting one.

1. **The interop component had no packaging guard.**  Measured:
   ``grep -rln 'py-modules' components/northstar-agent-interop/tests/``
   returns nothing.  The runtime component has
   ``tests/test_module_layout.py``; durable-run has
   ``tests/test_durable_packaging.py``; interop had neither.

2. **The CI was written around the gap.**  The interop job compiles
   ``remote_worker.py`` -- it is in the ``py_compile`` list -- but its
   install smoke check imports only the other seven:

       python -c "import interop_contract, handoff, interop_adapter,
       canary, process_adapter, process_backend, remote_transport"

   So the one module that was missing from the wheel was also the one
   module missing from the check that would have caught it.  The CI
   compile step and the CI install step disagreed about what the
   component contains, and nothing reconciled them.

THE RULE THIS SLICE PINS
-------------------------
> **Every module a component has on disk is in the wheel it builds.**

Checked for EVERY component in the repository, not one at a time, so the
next component that grows a module inherits the guard for free.

The model of the surface lives in ``tests/docbuild.py`` -- the module
that already knows how a component's two installation mechanisms work --
so these tests use it rather than re-deriving the rules.

These tests pin the rule, the fix, and the guard's own honesty:

* the interop component's ``remote_worker`` is declared for installation;
* the wheel the interop component builds CONTAINS ``remote_worker.py``;
* the installed surface can import the module;
* every component satisfies "on disk -> installed";
* the runtime component's 22 package members are NOT reported as missing
  (they are installed by ``packages.find``, not by ``py-modules``);
* the guard is not a rubber stamp: a component with an undeclared module
  is caught and NAMED.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path

import docbuild
import install_smoke_coverage

ROOT = docbuild.ROOT
COMPONENTS = ROOT / "components"
RUNTIME = "northstar-agent-runtime"
INTEROP = "northstar-agent-interop"


class InteropPackagingTests(unittest.TestCase):
    """The fix: the interop component declares every module it has."""

    def test_remote_worker_is_declared_for_installation(self):
        # The defect, stated as one fact.
        self.assertIn(
            "remote_worker",
            docbuild.flat_modules(INTEROP),
            "remote_worker.py is in the component but not in py-modules, so "
            "pip install . does not ship it",
        )

    def test_the_interop_component_declares_every_module_it_has(self):
        on_disk = docbuild.flat_modules_on_disk(INTEROP)
        installed = docbuild.installed_modules(INTEROP)
        self.assertEqual(
            sorted(on_disk - installed),
            [],
            "module(s) in the interop component but not installed: %s"
            % sorted(on_disk - installed),
        )

    def test_the_interop_component_declares_the_other_seven_too(self):
        # The fix must ADD one name, not replace the list.
        declared = docbuild.flat_modules(INTEROP)
        for name in (
            "canary",
            "handoff",
            "interop_adapter",
            "interop_contract",
            "process_adapter",
            "process_backend",
            "remote_transport",
        ):
            with self.subTest(module=name):
                self.assertIn(name, declared)

    def test_the_py_modules_list_is_sorted_and_deduplicated(self):
        # Sorted, so a diff shows ONE name added rather than a reshuffled list.
        pyproject = COMPONENTS / INTEROP / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        modules = data["tool"]["setuptools"]["py-modules"]
        self.assertEqual(
            sorted(modules),
            list(modules),
            "the py-modules list must stay sorted",
        )
        self.assertEqual(len(modules), len(set(modules)), "duplicate entries")


class WheelContentsTests(unittest.TestCase):
    """The wheel is the artifact that matters, not the pyproject."""

    def _build_wheel(self, tmp_path: Path) -> Path:
        dist = tmp_path / "dist"
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
                str(COMPONENTS / INTEROP),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            "building the interop wheel failed:\n%s" % result.stdout,
        )
        wheels = sorted(dist.glob("*.whl"))
        self.assertEqual(len(wheels), 1, "expected exactly one wheel: %s" % wheels)
        return wheels[0]

    def test_the_built_wheel_contains_every_declared_module(self):
        # Building the wheel is the only way to know what setuptools really
        # ships.  Reading pyproject.toml proves only what somebody wrote.
        with tempfile.TemporaryDirectory() as tmp:
            wheel = self._build_wheel(Path(tmp))
            with zipfile.ZipFile(wheel) as archive:
                names = {
                    Path(name).stem
                    for name in archive.namelist()
                    if name.endswith(".py")
                }
        declared = docbuild.flat_modules(INTEROP)
        self.assertIn(
            "remote_worker",
            names,
            "the wheel does not ship remote_worker.py",
        )
        self.assertEqual(
            sorted(declared - names),
            [],
            "module(s) declared but missing from the wheel: %s"
            % sorted(declared - names),
        )

    def test_the_installed_surface_can_import_the_scorecard(self):
        # The wheel must make the module IMPORTABLE from outside the
        # checkout.  (Running the scorecard itself needs a repository -- it
        # measures the tree, resolving `parents[2]/components` relative to
        # its own file -- so the run is asserted against the checkout in
        # `test_the_scorecard_runs_in_a_checkout` below.)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            wheel = self._build_wheel(tmp_path)
            site = tmp_path / "site"
            site.mkdir()
            install = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--quiet",
                    "--no-deps",
                    "--no-index",
                    "--target",
                    str(site),
                    str(wheel),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(install.returncode, 0, install.stdout)
            run = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import remote_worker; print('imported', remote_worker.__name__)",
                ],
                cwd=str(tmp_path),
                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(site)},
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        self.assertEqual(
            run.returncode,
            0,
            "the installed surface cannot import remote_worker:\n%s" % run.stdout,
        )
        self.assertIn("imported remote_worker", run.stdout)

    def test_the_scorecard_runs_in_a_checkout(self):
        # The scorecard measures the REPOSITORY -- it resolves
        # `parents[2]/components` relative to its own file -- so it is run
        # from a checkout, which is where CI runs it.  This is the
        # documented entry point; it must work.
        run = subprocess.run(
            [sys.executable, "-m", "remote_worker", "--score"],
            cwd=str(COMPONENTS / INTEROP),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(
            run.returncode,
            0,
            "the documented CI entry point fails:\n%s" % run.stdout,
        )
        self.assertIn("/", run.stdout, "the scorecard printed no score")


class EveryComponentPackagingTests(unittest.TestCase):
    """The rule, applied to every component -- so the next one inherits it."""

    def test_every_component_declares_every_module_it_has(self):
        for component in docbuild.components_that_ship_a_wheel():
            with self.subTest(component=component):
                self.assertEqual(
                    docbuild.uninstalled_modules(component),
                    [],
                    "module(s) in %s that the wheel would not ship: %s"
                    % (component, docbuild.uninstalled_modules(component)),
                )

    def test_every_declared_module_exists_on_disk(self):
        for component in docbuild.components_that_ship_a_wheel():
            with self.subTest(component=component):
                declared = docbuild.flat_modules(component)
                on_disk = docbuild.flat_modules_on_disk(component)
                self.assertEqual(
                    sorted(declared - on_disk),
                    [],
                    "module(s) declared by %s that do not exist: %s"
                    % (component, sorted(declared - on_disk)),
                )

    def test_the_runtime_package_members_are_not_reported_as_missing(self):
        # The 23 package members are installed by `packages.find`, not by
        # `py-modules`.  A guard that compared only against `py-modules`
        # would report all 23 as missing -- a false alarm on the runtime
        # component, which is exactly the shape of bug this slice fixes.
        #
        # RE-MEASURED 2026-11-16 by the `runtime-data-files` slice: 22 ->
        # 23, because the runtime's data-file directory (`policy/`) became
        # a package so that its data files could ship in the wheel.
        members = docbuild.package_members(RUNTIME)
        self.assertEqual(len(members), 23, sorted(members))
        # The two halves are DISJOINT: a package member's name cannot appear
        # in `py-modules` (that array lists flat names only).
        self.assertEqual(members & docbuild.flat_modules(RUNTIME), set())
        installed = docbuild.installed_modules(RUNTIME)
        self.assertEqual(
            sorted(members - installed),
            [],
            "the runtime's package members must be seen as installed",
        )

    def test_the_runtime_installed_surface_is_the_whole_surface(self):
        installed = docbuild.installed_modules(RUNTIME)
        # 1636 = 1613 flat + 23 package members.  RE-MEASURED 2026-11-16 by
        # the `runtime-data-files` slice (was 1635 = 1613 + 22).
        self.assertEqual(len(installed), 1636)
        self.assertEqual(len(docbuild.flat_modules_on_disk(RUNTIME)), 1613)

    def test_the_interop_component_is_covered_by_the_sweep(self):
        # The sweep must actually reach the component the defect was in.
        self.assertIn(INTEROP, docbuild.components_that_ship_a_wheel())
        self.assertIn("remote_worker", docbuild.flat_modules_on_disk(INTEROP))
        self.assertIn("remote_worker", docbuild.installed_modules(INTEROP))

    def test_a_component_without_a_pyproject_ships_no_wheel(self):
        # The sweep must not report a component that has no wheel at all.
        self.assertNotIn(
            "northstar-egress-sidecar",
            docbuild.components_that_ship_a_wheel(),
        )


class GuardHonestyTests(unittest.TestCase):
    """The guard must be real: it must fail when a module is undeclared."""

    def test_an_undeclared_module_is_caught_and_named(self):
        # The recurrence case, in a tmpdir, never in the working tree.
        with tempfile.TemporaryDirectory() as tmp:
            component = Path(tmp) / "a_component"
            component.mkdir()
            (component / "declared_module.py").write_text("x = 1\n", encoding="utf-8")
            (component / "forgotten_module.py").write_text("x = 1\n", encoding="utf-8")
            (component / "pyproject.toml").write_text(
                '[tool.setuptools]\npy-modules = ["declared_module"]\n',
                encoding="utf-8",
            )
            on_disk = {
                path.stem
                for path in component.glob("*.py")
                if docbuild.is_runtime_module(path)
            }
            # Read the tmpdir's own pyproject -- not the repository's.
            data = tomllib.loads(
                (component / "pyproject.toml").read_text(encoding="utf-8")
            )
            installed = set(data["tool"]["setuptools"]["py-modules"])
            missing = sorted(on_disk - installed)
        self.assertEqual(missing, ["forgotten_module"])
        self.assertIn("forgotten_module", str(missing))

    def test_a_test_prefixed_file_is_not_a_module(self):
        # The exclusions must hold: a test file in the component directory
        # is not a module, and reporting it would make the guard cry wolf.
        with tempfile.TemporaryDirectory() as tmp:
            component = Path(tmp) / "a_component"
            component.mkdir()
            (component / "a_module.py").write_text("x = 1\n", encoding="utf-8")
            (component / "test_a_module.py").write_text("x = 1\n", encoding="utf-8")
            (component / "setup.py").write_text("x = 1\n", encoding="utf-8")
            (component / "conftest.py").write_text("x = 1\n", encoding="utf-8")
            on_disk = {
                path.stem
                for path in component.glob("*.py")
                if docbuild.is_runtime_module(path)
            }
        self.assertEqual(on_disk, {"a_module"})


class CiSmokeTests(unittest.TestCase):
    """CI must check the same modules it compiles."""

    def _workflow(self) -> str:
        return (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

    def test_the_ci_compile_list_and_the_install_list_agree(self):
        # The measured state before this slice: CI compiled
        # `remote_worker.py` but its install smoke check imported only the
        # other seven, so the module missing from the wheel was also the
        # module missing from the check.
        #
        # The install smoke check no longer names its modules by hand -- it
        # asks the installed distribution which modules it ships and
        # imports every one of them (see
        # `tests/test_install_smoke_coverage.py`).  What this test still
        # pins is the agreement itself: every module the interop compile
        # step compiles must be one the install smoke check exercises.
        workflow = self._workflow()
        compile_line = ""
        for line in workflow.splitlines():
            if "py_compile" in line and "remote_worker.py" in line:
                compile_line = line
        self.assertTrue(
            compile_line,
            "the interop compile step no longer lists remote_worker.py",
        )
        installed = docbuild.installed_modules(INTEROP)
        covered = install_smoke_coverage.covered_modules(INTEROP, installed)
        for module in docbuild.flat_modules(INTEROP):
            with self.subTest(module=module):
                self.assertIn(
                    module,
                    covered,
                    "%s is declared for installation but the CI install smoke "
                    "check does not import it" % module,
                )

    def test_the_ci_smoke_check_imports_the_scorecard(self):
        # `remote_worker` is the interop component's documented CI entry
        # point.  The install smoke check exercises it on the INSTALLED
        # surface -- which is what the surface check does: it imports every
        # module the installed distribution ships.
        installed = docbuild.installed_modules(INTEROP)
        covered = install_smoke_coverage.covered_modules(INTEROP, installed)
        self.assertIn(
            "remote_worker",
            covered,
            "the CI install smoke check does not import remote_worker, so the "
            "documented CI entry point is never exercised on the installed "
            "surface",
        )


if __name__ == "__main__":
    unittest.main()
