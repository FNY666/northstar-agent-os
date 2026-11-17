"""Every component's ``py-modules`` list must be sorted and free of duplicates.

THE DEFECT, MEASURED (2026-11-17)
---------------------------------
``[tool.setuptools] py-modules`` is the array that says which flat modules
``pip install .`` puts on the path.  Measured over every component in the
repository:

| component | entries | distinct | duplicate names | sort inversions |
|---|---|---|---|---|
| northstar-agent-runtime | **1663** | **1613** | **50** | **9** |
| northstar-durable-run | 16 | 16 | 0 | **3** |
| northstar-run-evidence | 6 | 6 | 0 | **2** |
| northstar-agent-interop | 8 | 8 | 0 | 0 |
| northstar-host | 4 | 4 | 0 | 0 |
| northstar-run-contract | 5 | 5 | 0 | 0 |

The runtime's 50 duplicate names are the whole ``ba_01``..``ba_50`` family
appearing a second time at the end of the array; the durable-run and
run-evidence inversions are single misplaced names.

WHY IT SURVIVED
---------------
The repository has a guard for exactly this rule -- but only for the
**interop** component:

    tests/test_component_packaging_closure.py::
        test_the_py_modules_list_is_sorted_and_deduplicated

It reads ``components/northstar-agent-interop/pyproject.toml`` and never
looks at the runtime's.  The component with 1663 entries and by far the
most duplication had no such guard, so a rule that was already written
down was applied to one of six components.

And the runtime's own ``tests/test_module_layout.py`` reads the same
array with ``set(...)``:

    declared = set(pyproject["tool"]["setuptools"]["py-modules"])

which throws away exactly the information this defect is about.  A set
cannot hold a duplicate, so every check built on it is blind to one, and
blind to the order.

THE RULE THIS SLICE PINS
-------------------------
> **Every component's ``py-modules`` list is sorted and has no duplicate
> entries.**

Sorted so that adding a module is a ONE-LINE diff instead of a reshuffle,
and deduplicated so the array says what it means to say.

WHAT DOES NOT CHANGE
--------------------
The **installed surface is unchanged**.  setuptools deduplicates the list
when it builds the wheel, so the wheel this slice's fix produces carries
exactly the same modules as the wheel it replaces.  That is asserted in
the runtime component's own suite
(``components/northstar-agent-runtime/tests/test_py_modules_list.py``),
which builds the wheel before and after and compares the shipped module
set.
"""
from __future__ import annotations

import unittest
from pathlib import Path

import py_modules_guard

ROOT = py_modules_guard.ROOT
COMPONENTS = py_modules_guard.COMPONENTS


class EveryComponentPyModulesTests(unittest.TestCase):
    """The rule, applied to every component -- so the next one inherits it."""

    def test_the_scan_reaches_every_component_with_a_py_modules_list(self):
        # A guard that scanned one component would pass vacuously if the
        # scan silently stopped finding components.
        found = py_modules_guard.components_with_py_modules()
        names = {name for name, _ in found}
        self.assertGreaterEqual(
            len(names),
            6,
            "the scan found only %d components: %s" % (len(names), sorted(names)),
        )
        self.assertIn("northstar-agent-runtime", names)
        self.assertIn("northstar-agent-interop", names)

    def test_every_py_modules_list_is_sorted_and_deduplicated(self):
        problems: list[str] = []
        for name, modules in py_modules_guard.components_with_py_modules():
            problems.extend(
                py_modules_guard.sortedness_problems(COMPONENTS / name, modules)
            )
        self.assertEqual(
            problems,
            [],
            "\n".join(problems),
        )

    def test_no_component_declares_the_same_module_twice_in_the_file(self):
        # The TOML array is parsed as a list, so a repeated NAME is visible
        # above.  This checks the file itself has no repeated line, which
        # would catch a duplicate introduced by a bad edit that TOML still
        # parses -- and which a merge conflict marker could leave behind.
        for component in sorted(COMPONENTS.iterdir()):
            pyproject = component / "pyproject.toml"
            if not pyproject.is_file():
                continue
            repeated = py_modules_guard.repeated_lines(pyproject)
            with self.subTest(component=component.name):
                self.assertEqual(
                    repeated,
                    [],
                    "%s: repeated entries in pyproject.toml: %s"
                    % (component.name, repeated),
                )

    def test_no_py_modules_list_is_empty(self):
        # A list that became empty would satisfy "sorted and deduplicated"
        # and satisfy nothing else.
        for name, modules in py_modules_guard.components_with_py_modules():
            with self.subTest(component=name):
                self.assertGreater(len(modules), 0)


if __name__ == "__main__":
    unittest.main()
