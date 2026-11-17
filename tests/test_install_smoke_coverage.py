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
