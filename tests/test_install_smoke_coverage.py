"""Install-smoke coverage: every module a component ships must be imported
by that component's CI packaging smoke step.

A packaging smoke step is the check that proves the INSTALLED SURFACE
works.  It installs the wheel, moves to a directory that is not the
source tree, and imports the component's modules.  A shipped module that
the step never reaches is a module the step cannot notice breaking.

The rule pinned here:

> **Every module a component ships is imported by that component's CI
> packaging smoke step.**

The detector lives in ``tests/install_smoke_coverage.py`` rather than in
this file, for the same reason ``tests/py_modules_guard.py`` and
``tests/ci_compile_coverage.py`` do:  the mutant probe mutates a MODULE
and reruns the slice's tests, and a test file is excluded from the probe
by name.
"""
from __future__ import annotations

import sys
import ast
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import docbuild  # noqa: E402
import install_smoke_coverage as isc  # noqa: E402

WHEEL_COMPONENTS = [
    "northstar-agent-runtime",
    "northstar-agent-interop",
    "northstar-durable-run",
    "northstar-host",
    "northstar-run-contract",
    "northstar-run-evidence",
]


class InstallSmokeCoverageTests(unittest.TestCase):
    """The rule, against the REAL workflow."""

    def test_every_wheel_component_has_a_smoke_step(self):
        missing = isc.missing_smoke_steps(WHEEL_COMPONENTS)
        self.assertEqual(
            missing,
            [],
            "these components ship a wheel but have no CI packaging smoke "
            "step, so their installed surface is never checked at all: %s"
            % ", ".join(missing),
        )

    def test_every_shipped_module_is_imported_by_the_smoke_step(self):
        report = []
        for component in WHEEL_COMPONENTS:
            shipped = docbuild.installed_modules(component)
            uncovered = isc.uncovered_modules(component, shipped)
            if uncovered:
                report.append(
                    "%s: %d of %d shipped modules are never imported by its "
                    "CI packaging smoke step: %s"
                    % (
                        component,
                        len(uncovered),
                        len(shipped),
                        ", ".join(sorted(uncovered)[:12]),
                    )
                )
        self.assertEqual(
            report,
            [],
            "the CI packaging smoke step must import every module the "
            "component ships, so a module that breaks in the installed "
            "wheel is caught:\n  " + "\n  ".join(report),
        )

    def test_the_scan_finds_the_smoke_steps(self):
        # A guard that silently stopped finding the smoke steps would pass
        # vacuously, so assert the scan really locates them.
        for component in WHEEL_COMPONENTS:
            with self.subTest(component=component):
                steps = isc.steps_for(component)
                self.assertTrue(
                    steps,
                    "the scan found no packaging smoke step for %s"
                    % component,
                )

    def test_the_runtime_smoke_step_reaches_the_whole_installed_surface(self):
        shipped = docbuild.installed_modules("northstar-agent-runtime")
        self.assertGreater(len(shipped), 1600)
        uncovered = isc.uncovered_modules("northstar-agent-runtime", shipped)
        self.assertEqual(
            sorted(uncovered),
            [],
            "the runtime's packaging smoke step must reach every module the "
            "runtime ships: %d of %d are unreached"
            % (len(uncovered), len(shipped)),
        )


class GuardUnitTests(unittest.TestCase):
    """The detector against CRAFTED workflows.

    The repository-wide checks read the REAL workflow, which -- once the
    fix lands -- covers everything.  On their own they cannot tell a
    working detector from one that never fires.
    """

    def test_a_smoke_step_with_no_imports_covers_nothing(self):
        workflow = (
            "    - name: Smoke\n"
            "      working-directory: components/northstar-host\n"
            '      run: python -c "print(1)"\n'
        )
        steps = isc.smoke_steps(workflow)
        self.assertEqual(isc.steps_for("northstar-host", steps), [])

    def test_a_from_import_names_the_module_not_the_attribute(self):
        # `from evidence_chain import EvidenceChain` exercises the MODULE
        # evidence_chain; EvidenceChain is an attribute of it.
        self.assertEqual(
            isc.imported_names("from evidence_chain import EvidenceChain"),
            {"evidence_chain"},
        )
        self.assertEqual(
            isc.imported_names("from a import b, c"),
            {"a"},
        )

    def test_a_comma_separated_import_clause_yields_every_name(self):
        self.assertEqual(
            isc.imported_names("import a, b, c"),
            {"a", "b", "c"},
        )

    def test_a_malformed_program_yields_no_names_instead_of_raising(self):
        self.assertEqual(isc.imported_names("import (((("), set())

    def test_a_step_in_the_wrong_directory_belongs_to_that_directory(self):
        workflow = (
            "    - name: Smoke\n"
            "      working-directory: components/northstar-egress-sidecar\n"
            '      run: python -c "import contract"\n'
        )
        steps = isc.smoke_steps(workflow)
        self.assertTrue(isc.steps_for("northstar-egress-sidecar", steps))
        self.assertEqual(isc.steps_for("northstar-host", steps), [])

    def test_a_component_with_no_smoke_step_is_named_not_vacuously_covered(self):
        steps = isc.smoke_steps("jobs:\n  x:\n    run: echo hello\n")
        missing = isc.missing_smoke_steps(
            ["northstar-host", "northstar-run-contract"], steps
        )
        self.assertEqual(
            missing,
            ["northstar-host", "northstar-run-contract"],
        )

    def test_a_surface_step_covers_the_whole_installed_surface(self):
        # A step that asks the installed distribution which modules it
        # ships cannot omit one: it does not name them.
        workflow = (
            "    - name: Smoke\n"
            "      working-directory: components/northstar-host\n"
            "      run: python scripts/check_installed_surface.py northstar-host\n"
        )
        steps = isc.smoke_steps(workflow)
        component_steps = isc.steps_for("northstar-host", steps)
        self.assertEqual(len(component_steps), 1)
        self.assertEqual(component_steps[0].kind, "SURFACE")
        self.assertTrue(component_steps[0].covers_everything)

    def test_a_surface_step_must_name_the_components_own_distribution(self):
        # A surface step asks the INSTALLED distribution which modules it
        # ships.  If it names a DIFFERENT distribution -- a copy-paste
        # error -- it checks the wrong component's surface while looking
        # complete, which is worse than a step that names too little.
        workflow = (
            "    - name: Smoke\n"
            "      working-directory: components/northstar-host\n"
            "      run: python $REPO/scripts/check_installed_surface.py northstar-run-contract\n"
        )
        steps = isc.smoke_steps(workflow)
        shipped = docbuild.installed_modules("northstar-host")
        # The crafted step covers NONE of the host's surface: it names a
        # different distribution, so it checks somebody else's modules.
        covered = isc.covered_modules("northstar-host", shipped, steps)
        self.assertEqual(
            sorted(set(shipped) - covered),
            ["authorization", "host_audit", "host_policy", "workspace"],
            "a surface step that checks another component's distribution "
            "must not count as covering this component's surface",
        )

    def test_an_imports_step_does_not_cover_everything(self):
        workflow = (
            "    - name: Smoke\n"
            "      working-directory: components/northstar-host\n"
            '      run: python -c "import authorization"\n'
        )
        steps = isc.smoke_steps(workflow)
        component_steps = isc.steps_for("northstar-host", steps)
        self.assertEqual(component_steps[0].kind, "IMPORTS")
        self.assertFalse(component_steps[0].covers_everything)

    def test_reachability_follows_the_components_own_import_graph(self):
        graph = {"runner": {"event_store"}, "event_store": set()}
        shipped = {"runner", "event_store", "orphan"}
        covered = isc.reachable({"runner"}, graph, shipped)
        self.assertEqual(covered, {"runner", "event_store"})
        self.assertNotIn("orphan", covered)

    def test_reachability_of_a_package_reaches_its_members(self):
        shipped = {"tools", "tools.verify_invariants"}
        covered = isc.reachable({"tools"}, {}, shipped)
        self.assertEqual(covered, shipped)

    def test_a_lazy_import_inside_a_function_is_not_an_import_time_edge(self):
        # An import inside a function body runs when the function is
        # called, not when the module is imported, so the smoke step does
        # not exercise it.
        source = (
            "def helper():\n"
            "    import json\n"
            "    return json\n"
        )
        tree = __import__("ast").parse(source)
        self.assertEqual(isc._import_time_dependencies(tree), set())

    def test_a_class_body_import_is_an_import_time_edge(self):
        source = "class Thing:\n    import json\n"
        tree = __import__("ast").parse(source)
        self.assertEqual(isc._import_time_dependencies(tree), {"json"})

    def test_uncovered_modules_names_what_the_step_misses(self):
        shipped = {"a", "b"}
        graph = {"a": set(), "b": set()}
        steps = [
            isc.SmokeStep("components/northstar-host", "IMPORTS", frozenset({"a"}))
        ]
        covered = isc.covered_modules("northstar-host", shipped, steps)
        self.assertEqual(sorted(set(shipped) - covered), ["b"])


if __name__ == "__main__":
    unittest.main()


class SmokeGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of each guard in ``install_smoke_coverage``.

    Four planted faults survived this slice's suite:

      and@75   the "is absolute" half of the ``from`` import guard
      eq@188   the ``__init__`` branch of the module-path resolver
      or@252   the "is absolute" half of the import-time dependency guard
      and@283  the "is not already seen" half of the reachability walk

    All four are killable and are driven below.
    """

    # --- and@75: the "is absolute" half --------------------------------
    def test_a_relative_import_contributes_no_module_name(self):
        """`and@75`: the ``level == 0`` half.

        A relative import (``from . import sibling``) has no absolute
        module name, so it contributes no name to the scanner.  Under
        the mutant (``and`` -> ``or``) the relative import's name is
        added -- and a smoke step would then be credited with covering
        a module it never imports.
        """
        self.assertEqual(isc.imported_names("from .pkg import x"), set())

    def test_an_absolute_import_contributes_its_module_name(self):
        """`and@75`: the control -- an absolute import names its module."""
        self.assertEqual(isc.imported_names("from pkg.mod import x"), {"pkg"})

    def test_a_plain_import_still_contributes_its_name(self):
        """`and@75`: the other import form."""
        self.assertEqual(isc.imported_names("import os"), {"os"})

    # --- or@252: the "is absolute" half --------------------------------
    def test_a_relative_import_is_not_an_import_time_dependency(self):
        """`or@252`: the ``level != 0`` half.

        A relative import is not an import-time dependency on an
        absolute module -- the module it names is a sibling, not a
        shipped package.  Under the mutant (``or`` -> ``and``) the
        relative import's module is added to the dependency set, and
        the smoke step would be credited with covering it.
        """
        tree = ast.parse("from .pkg import x\n")
        self.assertEqual(isc._import_time_dependencies(tree), set())

    def test_an_absolute_from_import_is_an_import_time_dependency(self):
        """`or@252`: the control -- an absolute ``from`` import is."""
        tree = ast.parse("from pkg.mod import x\n")
        self.assertEqual(
            isc._import_time_dependencies(tree), {"pkg.mod", "pkg.mod.x"}
        )

    def test_a_plain_import_is_an_import_time_dependency(self):
        """`or@252`: the other import form."""
        tree = ast.parse("import os\n")
        self.assertEqual(isc._import_time_dependencies(tree), {"os"})

    # --- and@283: the "not already seen" half --------------------------
    def test_an_unshipped_dependency_is_not_reached(self):
        """`and@283`: the "is shipped" half.

        The walk pushes a dependency only when it is SHIPPED and NOT
        already seen.  Under the mutant (``and`` -> ``or``) the
        "is shipped" half stops mattering -- a dependency that is not
        shipped is pushed anyway, and lands in the covered set.

        That is the false claim that matters: the covered set is what
        says a module IS exercised by the smoke step, and an unshipped
        module in it is a module nobody can import.
        """
        graph = {"a": {"z", "nope"}}
        shipped = {"a", "z"}
        covered = isc.reachable({"a"}, graph, shipped)
        self.assertEqual(covered, {"a", "z"})
        self.assertNotIn("nope", covered)

    def test_a_cyclic_import_graph_terminates(self):
        """`and@283`: the other half -- the walk is finite.

        Two modules that depend on each other must not make the walk
        loop forever.
        """
        graph = {"a": {"z"}, "z": {"a"}}
        shipped = {"a", "z"}
        covered = isc.reachable({"a"}, graph, shipped)
        self.assertEqual(covered, {"a", "z"})

    # --- eq@188: the `__init__` branch ---------------------------------
    def test_a_package_initializer_resolves_to_its_init_file(self):
        """`eq@188`: the initializer branch.

        A package member named ``__init__`` resolves to the package's
        ``__init__.py``.  Under the mutant (``==`` -> ``!=``) the two
        branches are exchanged, and EVERY package member resolves to
        the initializer instead -- so a module that does not exist
        would be reported as present.
        """
        source = isc.module_source("northstar-agent-runtime", "tools.__init__")
        self.assertIsNotNone(source)
        self.assertEqual(source.name, "__init__.py")
        self.assertEqual(source.parent.name, "tools")

    def test_a_package_member_resolves_to_its_module_file(self):
        """`eq@188`: the other branch -- the ordinary member.

        This is the discriminating input: a package member that is NOT
        the initializer must resolve to its OWN file.  Under the mutant
        it would resolve to the package's ``__init__.py`` instead.
        """
        source = isc.module_source("northstar-agent-runtime", "tools.verify_invariants")
        self.assertIsNotNone(source)
        self.assertEqual(source.name, "verify_invariants.py")
        self.assertEqual(source.parent.name, "tools")
