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

import ast
import contextlib
import io
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path
from unittest import mock

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
        self.assertEqual(len(installed), 1642)
        self.assertEqual(len(docbuild.flat_modules_on_disk(RUNTIME)), 1619)

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


class DocbuildGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of each guard in ``tests/docbuild.py``.

    ``docbuild`` renders the reference pages, so every guard in it decides
    what a reader is shown.  Each guard below is a double guard -- a type
    half joined to a second half by ``and``, or a bound compared against a
    constant -- and the component-packaging-closure slice's own suite
    drove only ONE half of each.  Every one of these planted faults
    therefore SURVIVED that suite:

      gt@429   the summary cap
      and@440  the leading self/cls drop
      and@464  the ``@property`` decorator (Name form)
      retT@465 its return
      and@466  the ``@x.property`` decorator (Attribute form)
      retT@467 its return
      retF@468 the fall-through
      and@488  the module-level function filter
      and@495  the module-level class filter
      and@503  the class-member filter
      eq@540   the trailing-blank-line trim
      eq@680   the exclusion-family lookup
      lt@755   the docstring-tag split
      retF@756 its "no tag" return
      or@808   the probe-corpus name test
      and@812  the guard-detector rule

    Each test here fails when its own planted fault is applied alone.
    """

    # --- gt@429: the summary cap -----------------------------------------
    def test_a_summary_at_the_cap_is_not_truncated(self):
        """`gt@429`: the cap is STRICT.

        A summary whose length is exactly the cap must come back whole.
        With `> -> >=` it would be truncated and given an ellipsis.
        """
        text = "x" * 300
        self.assertEqual(docbuild._summary(text, cap=300), text)

    def test_a_summary_one_over_the_cap_is_truncated(self):
        """`gt@429`: the bound, from the other side."""
        summary = docbuild._summary("x" * 301, cap=300)
        self.assertEqual(len(summary), 300)
        self.assertTrue(summary.endswith("…"))

    def test_a_summary_shorter_than_the_cap_is_untouched(self):
        """`gt@429`: the control -- under the cap, nothing is dropped."""
        text = "short summary"
        self.assertEqual(docbuild._summary(text, cap=300), text)

    # --- and@440: the leading self/cls drop ------------------------------
    def test_the_leading_self_is_dropped_from_a_signature(self):
        """`and@440`: both halves hold, so the drop happens."""
        node = ast.parse("def method(self, value):\n    pass\n").body[0]
        self.assertEqual(docbuild._signature(node), "method(value)")

    def test_a_non_self_first_parameter_is_kept(self):
        """`and@440`: the other half.

        A first parameter that is not a self-name must be kept -- the
        signature would otherwise name the wrong thing.
        """
        node = ast.parse("def method(value, other):\n    pass\n").body[0]
        self.assertEqual(docbuild._signature(node), "method(value, other)")

    def test_a_method_with_no_parameters_renders_with_empty_parens(self):
        """`and@440`: the empty-list half.

        With no positionals at all the first half is False, so the drop
        must not happen -- and the rendering must not crash on the
        `positionals[0]` it must not reach.
        """
        node = ast.parse("def method():\n    pass\n").body[0]
        self.assertEqual(docbuild._signature(node), "method()")

    def test_a_leading_cls_is_dropped_too(self):
        """`and@440`: the self-name set is not just ``self``."""
        node = ast.parse("def method(cls, value):\n    pass\n").body[0]
        self.assertEqual(docbuild._signature(node), "method(value)")

    # --- and@464 / retT@465 / and@466 / retT@467 / retF@468: properties ---
    def test_a_property_decorator_is_recognised(self):
        """`and@464` and `retT@465`: the bare ``@property`` name form."""
        node = ast.parse("@property\ndef value(self):\n    pass\n").body[0]
        self.assertTrue(docbuild._is_property(node))

    def test_a_cached_property_decorator_is_recognised(self):
        """`and@464`: the other name in the same set."""
        node = ast.parse("@cached_property\ndef value(self):\n    pass\n").body[0]
        self.assertTrue(docbuild._is_property(node))

    def test_an_attribute_property_decorator_is_recognised(self):
        """`and@466` and `retT@467`: the ``@x.property`` attribute form."""
        node = ast.parse("@functools.cached_property\ndef value(self):\n    pass\n").body[0]
        self.assertTrue(docbuild._is_property(node))

    def test_a_non_property_decorator_is_not_a_property(self):
        """`retF@468`: the fall-through.

        A plain decorator must not be read as a property -- otherwise the
        reference page would drop the parentheses from a method that has
        arguments.
        """
        node = ast.parse("@staticmethod\ndef value(x):\n    pass\n").body[0]
        self.assertFalse(docbuild._is_property(node))

    def test_an_undecorated_function_is_not_a_property(self):
        """`retF@468`: the fall-through, with no decorator at all."""
        node = ast.parse("def value(self):\n    pass\n").body[0]
        self.assertFalse(docbuild._is_property(node))

    def test_a_property_member_is_rendered_without_parentheses(self):
        """`and@464`/`and@466`/`retT@465`/`retT@467`: through the renderer.

        The renderer consults `_is_property` to decide whether a class
        member is written as ``name`` (property) or ``name(args)``.  The
        fixture module carries one property and one ordinary method.
        """
        source = (
            "class Sample:\n"
            "    @property\n"
            "    def value(self):\n"
            "        \"\"\"A value.\"\"\"\n"
            "        return 1\n"
            "\n"
            "    def compute(self, factor):\n"
            "        \"\"\"A method.\"\"\"\n"
            "        return factor\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "sample.py"
            path.write_text(source, encoding="utf-8")
            with mock.patch.object(docbuild, "ROOT", root):
                lines = docbuild._render_module("northstar-agent-runtime", "sample", path)
        body = "\n".join(lines)
        self.assertIn("- `value` (property)", body)
        self.assertIn("- `compute(factor)`", body)
        self.assertNotIn("- `value()`", body)

    # --- and@488 / and@495 / and@503: the private-name filters -----------
    def test_a_private_module_level_function_is_not_rendered(self):
        """`and@488`: the name filter on module-level functions."""
        source = (
            "def _hidden():\n"
            "    \"\"\"Hidden.\"\"\"\n"
            "\n"
            "def visible():\n"
            "    \"\"\"Visible.\"\"\"\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "sample.py"
            path.write_text(source, encoding="utf-8")
            with mock.patch.object(docbuild, "ROOT", root):
                lines = docbuild._render_module("northstar-agent-runtime", "sample", path)
        body = "\n".join(lines)
        self.assertNotIn("`_hidden()`", body)
        self.assertIn("`visible()`", body)

    def test_a_private_class_is_not_rendered(self):
        """`and@495`: the name filter on module-level classes."""
        source = (
            "class _Hidden:\n"
            "    \"\"\"Hidden.\"\"\"\n"
            "\n"
            "class Visible:\n"
            "    \"\"\"Visible.\"\"\"\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "sample.py"
            path.write_text(source, encoding="utf-8")
            with mock.patch.object(docbuild, "ROOT", root):
                lines = docbuild._render_module("northstar-agent-runtime", "sample", path)
        body = "\n".join(lines)
        self.assertNotIn("`_Hidden`", body)
        self.assertIn("`Visible`", body)

    def test_a_private_class_member_is_not_rendered(self):
        """`and@503`: the name filter on class members."""
        source = (
            "class Visible:\n"
            "    \"\"\"Visible.\"\"\"\n"
            "\n"
            "    def _hidden(self):\n"
            "        \"\"\"Hidden.\"\"\"\n"
            "\n"
            "    def shown(self):\n"
            "        \"\"\"Shown.\"\"\"\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "sample.py"
            path.write_text(source, encoding="utf-8")
            with mock.patch.object(docbuild, "ROOT", root):
                lines = docbuild._render_module("northstar-agent-runtime", "sample", path)
        body = "\n".join(lines)
        self.assertNotIn("- `_hidden`", body)
        self.assertIn("- `shown()`", body)

    # --- eq@540: the trailing-blank-line trim ---------------------------
    def test_the_rendered_page_ends_with_exactly_one_newline(self):
        """`eq@540`: the trailing-blank trim.

        The rendered reference page must end with exactly one final
        newline -- no run of blank lines at the end.  With `== -> !=`
        the trim would stop at the first non-blank line and the page
        would keep its trailing blanks.
        """
        page = docbuild.render_page("northstar-run-contract")
        self.assertTrue(page.endswith("\n"))
        self.assertFalse(page.endswith("\n\n"))

    def test_no_rendered_page_ends_with_a_blank_line(self):
        """`eq@540`: across every component the renderer builds."""
        for component in docbuild.MANIFEST:
            with self.subTest(component=component):
                page = docbuild.render_page(component)
                self.assertFalse(page.endswith("\n\n"))

    # --- eq@680: the exclusion-family lookup ----------------------------
    def test_an_exclusion_family_is_found_by_its_name(self):
        """`eq@680`: the name that IS a family."""
        declared = docbuild.EXCLUSION_FAMILIES[1]
        self.assertEqual(docbuild.family_members(declared.name), declared.member_names())

    def test_an_unknown_family_name_is_refused(self):
        """`eq@680`: the name that is NOT a family.

        A name that matches no family must raise KeyError -- it must
        not be handed the FIRST family's members, which would classify
        a module under a family it does not belong to.
        """
        with self.assertRaises(KeyError):
            docbuild.family_members("no-such-family")

    def test_a_family_object_is_used_directly(self):
        """`eq@680`: the control -- an object is not looked up by name."""
        declared = docbuild.EXCLUSION_FAMILIES[1]
        self.assertEqual(docbuild.family_members(declared), declared.member_names())

    # --- lt@755 / retF@756: the design-tag split ------------------------
    def test_a_module_with_a_docstring_but_no_tag_has_no_design_tag(self):
        """`lt@755`: the split happened, and the tag is absent.

        The docstring is present, so the split succeeds; the pattern
        does not match, so the answer is False.
        """
        self.assertFalse(
            docbuild._has_design_tag("northstar-agent-runtime", "egress_client")
        )

    def test_a_module_without_a_docstring_has_no_design_tag(self):
        """`lt@755` and `retF@756`: the "no docstring" answer.

        A module with no source at all yields an empty string, so there
        are no docstring parts to split and the guard must say False.
        """
        self.assertFalse(
            docbuild._has_design_tag("northstar-agent-runtime", "no_such_module_xyz")
        )

    def test_a_source_with_a_single_docstring_marker_is_still_scanned(self):
        """`lt@755`: the bound, from the side that shows it is strict.

        The guard is ``if len(parts) < 2: return False``.  A source
        whose docstring marker has no closing marker splits into exactly
        TWO parts, and the second still carries the tag -- so the tag
        must be found.  With the bound weakened to ``<= 2`` the guard
        would return False and the tag would be missed.
        """
        source = '"""Module docstring carrying (D-OUT-123) and no closing marker'
        with mock.patch.object(docbuild, "_module_source", return_value=source):
            self.assertTrue(docbuild._has_design_tag("northstar-agent-runtime", "any"))

    def test_a_tagged_module_is_recognised(self):
        """The control: a module that really does carry the tag.

        ``out_def_36`` is a numbered-probe-family member whose docstring
        carries a ``(D-OUT-nnn)`` tag.
        """
        self.assertTrue(
            docbuild._has_design_tag("northstar-agent-runtime", "out_def_36")
        )

    # --- or@808: the probe-corpus name test ------------------------------
    def test_a_probe_named_module_is_a_probe_corpus(self):
        """`or@808`: the ``_probe`` suffix -- the first half.

        The two halves are the two spellings -- ``_probe`` and
        ``_probes``.  Both must be recognised, and the first is what
        this test drives.
        """
        kinds = docbuild.exclusion_reason_kinds("northstar-agent-runtime", "asi02_probe")
        self.assertIn("probe-corpus", kinds)

    def test_a_probes_named_module_is_a_probe_corpus(self):
        """`or@808`: the ``_probes`` suffix -- the second half."""
        kinds = docbuild.exclusion_reason_kinds(
            "northstar-agent-runtime", "approval_fatigue_probes"
        )
        self.assertIn("probe-corpus", kinds)

    def test_a_module_with_neither_suffix_is_not_a_probe_corpus(self):
        """`or@808`: the name that is neither.

        With the connective flipped to `and`, a module ending in
        ``_probe`` would no longer be a probe corpus -- and one ending
        in neither would have been checked only by the second half.
        """
        kinds = docbuild.exclusion_reason_kinds("northstar-agent-runtime", "egress_client")
        self.assertNotIn("probe-corpus", kinds)

    # --- and@812: the guard-detector rule -------------------------------
    def test_a_family_member_with_a_tag_is_not_a_guard_detector(self):
        """`and@812`: the second half of the rule.

        ``out_def_36`` is BOTH a numbered-probe-family member and
        tag-carrying.  The family is its reason -- it is a sibling in a
        numbered defence series -- so the tag rule must not claim it.
        """
        kinds = docbuild.exclusion_reason_kinds("northstar-agent-runtime", "out_def_36")
        self.assertIn("numbered-probe-family", kinds)
        self.assertNotIn("guard-detector", kinds)

    def test_a_mock_with_a_tag_is_not_a_guard_detector(self):
        """`and@812`: the other exclusion of the tag rule.

        ``bias_mock`` is a mock stand-in that also carries a design tag.
        The mock is its reason, so the tag rule must not claim it.
        """
        kinds = docbuild.exclusion_reason_kinds("northstar-agent-runtime", "bias_mock")
        self.assertIn("mock-stand-in", kinds)
        self.assertNotIn("guard-detector", kinds)

    def test_a_probe_corpus_is_not_a_guard_detector(self):
        """`and@812`: the probe rule does not carry a design tag.

        The kinds are disjoint, so a probe corpus must not also be
        reported as a guard detector.
        """
        kinds = docbuild.exclusion_reason_kinds("northstar-agent-runtime", "asi02_probe")
        self.assertIn("probe-corpus", kinds)
        self.assertNotIn("guard-detector", kinds)


class ComponentPackagingClosureGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of every guard in ``tests/docbuild.py``.

    These four slices SHARE one module -- ``tests/docbuild.py`` -- and the
    batch's planted-fault probe plants a fault in it and then runs EACH
    slice's OWN test file against it.  A killer test placed in one test
    file kills the mutant for that slice ONLY, so the same technique has to
    be applied in every one of the four files.

    The mutants that survived, per slice, measured with the batch's own
    probe (``b173-mutant.py --tries 64 --no-early-stop``, run against a
    copy of the tree with the unmutated module):

      exclusion-reasons           14 of 27 survived
      component-packaging-closure 20 of 27
      package-member-publication  13 of 27
      shipped-module-docs         12 of 27

    The union of the four survivor sets is the seventeen sites below.  Each
    one is a DOUBLE guard -- a type half joined to a second half by
    ``and``/``or``, or a bound compared against a constant -- and the
    existing suite drove only ONE half of each.  Under a planted fault the
    half that was never driven changes the answer, and the suite passes
    anyway.

      and@464   the ``@property`` decorator, Name form
      retT@465   its return
      retT@467   the ``@x.property`` decorator, Attribute form, its return
      eq@680     the exclusion-family lookup
      lt@755     the docstring-tag split
      retF@756   its "no tag" return
      or@808     the probe-corpus name test
      and@812    the guard-detector rule
      eq@1059    the runtime-module suffix
      and@1073   the wheel component sweep
      or@1151    the data-file scan
      eq@1157    the ``pyproject.toml`` exclusion
      or@1234    the staleness check
      or@1272    the external-link skip
      or@1298    the verify verdict
      or@1307    the argument check
      eq@1310    the build/verify dispatch

    Every test below fails when its own planted fault is applied alone.
    """

    # --- and@464 / retT@465: the Name-form property decorator ----------
    def test_a_name_decorator_that_is_not_a_property_is_not_a_property(self):
        """`and@464`: the second half of the Name-form guard.

        The guard is ``isinstance(decorator, ast.Name) AND decorator.id in
        {"property", "cached_property"}``.  The "is a known name" half
        never fires on ``@staticmethod`` -- only the type half does, and
        the type half is satisfied.  Under the mutant (``and`` -> ``or``)
        the guard would fire on ANY name decorator, and the reference
        page would drop the parentheses from a method that has arguments.
        """
        node = ast.parse("@staticmethod\ndef value(self):\n    pass\n").body[0]
        self.assertFalse(docbuild._is_property(node))

    def test_the_name_form_property_decorator_is_recognised(self):
        """`retT@465`: the return of the Name-form branch.

        A bare ``@property`` must still be recognised.  Under the mutant
        (``return True`` -> ``return False``) it would be reported as an
        ordinary method, so the page would show ``value()`` for a
        property.
        """
        node = ast.parse("@property\ndef value(self):\n    pass\n").body[0]
        self.assertTrue(docbuild._is_property(node))

    # --- retT@467: the Attribute-form property decorator ----------------
    def test_the_attribute_form_property_decorator_is_recognised(self):
        """`retT@467`: the return of the Attribute-form branch.

        ``@functools.cached_property`` is a property reached through an
        attribute, so it is this branch's own case.  Under the mutant
        (``return True`` -> ``return False``) it would lose its
        ``(property)`` marker on the reference page.
        """
        node = ast.parse(
            "@functools.cached_property\ndef value(self):\n    pass\n"
        ).body[0]
        self.assertTrue(docbuild._is_property(node))

    # --- eq@680: the exclusion-family lookup ----------------------------
    def test_a_family_lookup_returns_that_familys_members(self):
        """`eq@680`: the family that carries the requested name.

        ``family_members("ba")`` must return the ``ba`` family's members.
        Under the mutant (``==`` -> ``!=``) the lookup would accept the
        FIRST family whose name does NOT match, so a module would be
        classified under a family it does not belong to.
        """
        declared = docbuild.EXCLUSION_FAMILIES[1]
        self.assertEqual(
            docbuild.family_members(declared.name), declared.member_names()
        )
        self.assertNotEqual(
            docbuild.family_members(declared.name),
            docbuild.EXCLUSION_FAMILIES[0].member_names(),
        )

    # --- lt@755: the docstring split is strict --------------------------
    def test_a_single_docstring_marker_still_yields_the_tag(self):
        """`lt@755`: the bound, from the side that shows it is strict.

        The guard is ``if len(parts) < 2: return False``.  A source whose
        docstring marker has no closing marker splits into exactly TWO
        parts, and the second still carries the tag -- so the tag must be
        found.  With the bound weakened to ``<= 2`` the guard would
        return False and the tag would be missed.
        """
        source = '"""Module docstring carrying (D-OUT-123) and no closing marker'
        with mock.patch.object(docbuild, "_module_source", return_value=source):
            self.assertTrue(docbuild._has_design_tag(RUNTIME, "any"))

    # --- retF@756: the "no docstring at all" answer --------------------
    def test_a_source_with_no_docstring_marker_has_no_tag(self):
        """`retF@756`: the "there is no docstring" answer.

        A source with no ``\"\"\"`` marker at all splits into exactly ONE
        part, so there is nothing to scan and the answer must be False.
        Under the mutant (``return False`` -> ``return True``) every such
        module would be reported as carrying a design tag, and the
        guard-detector rule would claim modules that carry none.
        """
        with mock.patch.object(docbuild, "_module_source", return_value="x = 1\n"):
            self.assertFalse(docbuild._has_design_tag(RUNTIME, "any"))

    # --- or@808: the probe-corpus name test -----------------------------
    def test_the_probe_suffix_alone_makes_a_probe_corpus(self):
        """`or@808`: the ``_probe`` suffix -- the first half.

        The two halves are the two spellings -- ``_probe`` and
        ``_probes``.  Under the mutant (``or`` -> ``and``) a module ending
        in ``_probe`` would no longer be a probe corpus, so its exclusion
        would fall to a different reason kind.
        """
        kinds = docbuild.exclusion_reason_kinds(RUNTIME, "asi02_probe")
        self.assertIn("probe-corpus", kinds)

    # --- and@812: the guard-detector rule -------------------------------
    def test_an_untagged_module_is_not_a_guard_detector(self):
        """`and@812`: the half that has to be FALSE.

        ``egress_client`` carries no design tag, is in no family and is
        not a mock, so the tag rule must not claim it.  Under the mutant
        (``and`` -> ``or``) the second half -- ``"numbered-probe-family"
        not in kinds`` -- is true for every module, so EVERY module would
        be reported as a guard detector.
        """
        kinds = docbuild.exclusion_reason_kinds(RUNTIME, "egress_client")
        self.assertNotIn("guard-detector", kinds)

    # --- eq@1059: the runtime-module suffix ----------------------------
    def test_a_non_python_file_is_not_a_runtime_module(self):
        """`eq@1059`: the suffix half of the guard.

        The guard is ``path.is_file() AND path.suffix == ".py" AND ...``.
        A README is a file that is not Python, so it must not be counted
        as a runtime module.  Under the mutant (``==`` -> ``!=``) every
        non-Python file in a component directory would be counted, and
        the component's flat-module list would gain a name that is not a
        module at all.
        """
        readme = docbuild.ROOT / "components" / RUNTIME / "README.md"
        self.assertTrue(readme.is_file())
        self.assertFalse(docbuild.is_runtime_module(readme))

    # --- and@1073: the wheel component sweep ---------------------------
    def test_a_directory_without_a_pyproject_builds_no_wheel(self):
        """`and@1073`: the second half of the wheel sweep.

        A component directory with no ``pyproject.toml`` builds no wheel,
        so it must not be reported as shipping one.  Under the mutant
        (``and`` -> ``or``) the type half -- "it is a directory" -- would
        be enough, and every component directory would be reported.
        """
        wheels = docbuild.components_that_ship_a_wheel()
        self.assertIn(RUNTIME, wheels)
        self.assertNotIn("northstar-codex-sidecar", wheels)
        self.assertNotIn("northstar-egress-sidecar", wheels)

    # --- or@1151: the data-file scan -----------------------------------
    def test_only_data_suffixes_are_reported_as_data_files(self):
        """`or@1151`: the suffix half of the scan's skip rule.

        The rule is ``not path.is_file() OR path.suffix not in
        DATA_SUFFIXES`` -- skip anything that is not a data file.  A
        module's ``.py`` source is installed by ``py-modules`` and is not
        runtime data, so it must not be reported as one.  Under the mutant
        (``or`` -> ``and``) every file that EXISTS but is not a data file
        would be reported instead.
        """
        for name in docbuild.data_files_on_disk(RUNTIME):
            with self.subTest(name=name):
                self.assertTrue(name.endswith((".json", ".toml")), name)

    # --- eq@1157: the pyproject.toml exclusion -------------------------
    def test_the_pyproject_is_not_counted_as_a_data_file(self):
        """`eq@1157`: the packaging-configuration exclusion.

        A ``pyproject.toml`` is packaging configuration, not a file a
        module reads at runtime, so it must not be reported as a data
        file -- and the two files that ARE data files must still be
        reported.  Under the mutant (``==`` -> ``!=``) the exclusion
        would fire on every other file, and the two real data files
        would be reported INSTEAD.
        """
        found = docbuild.data_files_on_disk(RUNTIME)
        self.assertNotIn("pyproject.toml", found)
        self.assertIn("policy/dataflow.toml", found)
        self.assertIn("policy/deny_monotonicity_baseline.json", found)

    # --- or@1234: the staleness check ----------------------------------
    def test_a_stale_page_is_named_as_stale(self):
        """`or@1234`: the content half of the staleness rule.

        A committed page whose bytes differ from a fresh generation is
        stale and must be named.  Under the mutant (``or`` -> ``and``)
        the rule would only fire for a page that does not EXIST, so a
        page that is present but out of date would be reported as fresh
        -- which is exactly the drift the check exists to catch.
        """
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            (api / "northstar-run-contract.md").write_text("stale", encoding="utf-8")
            with mock.patch.object(docbuild, "API_DIR", api), mock.patch.object(
                docbuild,
                "build_all",
                return_value={"northstar-run-contract": "fresh"},
            ):
                self.assertEqual(docbuild.stale_pages(), ["northstar-run-contract"])

    # --- or@1272: the external-link skip -------------------------------
    def test_an_external_link_is_not_a_broken_link(self):
        """`or@1272`: the first half of the skip rule.

        An ``http(s)`` or ``mailto:`` link points off-site, so it is not
        an internal link and must not be reported as broken.  Under the
        mutant (``or`` -> ``and``) the emptiness half would be the only
        one left, so every external link would be resolved against the
        local tree and reported as broken.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "doc.md").write_text(
                "[site](https://example.com/page)\n\n[mail](mailto:someone@example.com)\n",
                encoding="utf-8",
            )
            with mock.patch.object(docbuild, "ROOT", root):
                self.assertEqual(docbuild.broken_links(), [])

    # --- or@1298: the verify verdict -----------------------------------
    def test_stale_pages_alone_make_verify_fail(self):
        """`or@1298`: the two halves of the verdict.

        Stale pages and broken links are two independent failures, and
        EITHER one must fail the check.  Under the mutant (``or`` ->
        ``and``) a run with stale pages but no broken links would be
        reported as OK -- and the stale pages would go unnoticed.
        """
        with mock.patch.object(
            docbuild, "stale_pages", return_value=["northstar-run-contract"]
        ), mock.patch.object(docbuild, "broken_links", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(docbuild.verify(), 1)

    # --- or@1307: the argument check -----------------------------------
    def test_running_with_no_argument_prints_the_usage(self):
        """`or@1307`: the emptiness half of the argument rule.

        With no argument at all there is no command, so the usage must
        be printed and the exit code must be 2.  Under the mutant
        (``or`` -> ``and``) the second half would be evaluated on an
        empty list and the guard would raise instead of refusing.
        """
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(docbuild.main([]), 2)

    def test_running_with_an_unknown_argument_prints_the_usage(self):
        """`or@1307`: the membership half of the argument rule.

        A command that is neither ``build`` nor ``verify`` must be
        refused with exit code 2.  Under the mutant (``or`` -> ``and``)
        an unknown command would fall through to the verify path.
        """
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
            docbuild, "verify", return_value=0
        ):
            self.assertEqual(docbuild.main(["nonsense"]), 2)

    # --- eq@1310: the build/verify dispatch ----------------------------
    def test_the_build_command_writes_the_pages(self):
        """`eq@1310`: the ``build`` half of the dispatch.

        ``build`` WRITES the pages.  Under the mutant (``==`` -> ``!=``)
        ``build`` would fall through to ``verify`` and write nothing, so
        the page would not exist afterwards.
        """
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            with mock.patch.object(docbuild, "API_DIR", api), mock.patch.object(
                docbuild,
                "build_all",
                return_value={"northstar-run-contract": "fresh"},
            ), mock.patch.object(docbuild, "verify", return_value=0), mock.patch.object(
                docbuild, "ROOT", api
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(docbuild.main(["build"]), 0)
            self.assertTrue((api / "northstar-run-contract.md").is_file())

    def test_the_verify_command_writes_nothing(self):
        """`eq@1310`: the ``verify`` half of the dispatch.

        ``verify`` CHECKS the pages and writes none of them.  Under the
        mutant (``==`` -> ``!=``) ``verify`` would regenerate the pages
        instead -- which would hide the very staleness it is meant to
        report.
        """
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            with mock.patch.object(docbuild, "API_DIR", api), mock.patch.object(
                docbuild, "build_all", return_value={"northstar-run-contract": "fresh"}
            ), mock.patch.object(docbuild, "verify", return_value=0), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(docbuild.main(["verify"]), 0)
            self.assertEqual(list(api.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
