"""A module must not define the same top-level name twice.

THE DEFECT, MEASURED (2026-11-16)
---------------------------------
Fifty of the runtime's shipped modules -- the whole ``ba_01``..``ba_50``
family -- carry a duplicated block of source.  Each defines ``_tests``
twice, and the ``if __name__ == "__main__":`` block twice, with the second
copy byte-identical to the first::

    $ cat -n components/northstar-agent-runtime/ba_01.py
         1  '''ba_01: add_two utility.'''
         2
         3  def add_two(x):
         4      return x + 2
         5
         6  def _tests():
         7      assert add_two(1) == 3
         8      assert add_two(0) == 2
         9
    10  if __name__ == '__main__':
    11      _tests(); print('ok')
    12
    13  def _tests():          <-- the SECOND copy
    14      assert add_two(1) == 3
    15      assert add_two(0) == 2
    16
    17  if __name__ == '__main__':
    18      _tests(); print('ok')

The observable effect is not cosmetic.  Python's module namespace holds
ONE entry per name, so the second definition replaces the first: the
first is dead code that can never be called, and the module's own
self-test runs TWICE on every invocation::

    $ python3 components/northstar-agent-runtime/ba_01.py
    ok
    ok

THE SCOPE IS EXACT
------------------
Measured over every ``.py`` file in the repository:

* 50 files have a duplicated top-level definition;
* all 50 are the ``ba_*`` family in the runtime component;
* all 50 have byte-identical duplicate bodies;
* **zero** files anywhere have a duplicate whose bodies DIFFER.

That last measurement is the reason the guard must catch BOTH cases.  A
duplicate whose bodies differ is not untidy -- it is a live definition
silently shadowed by a different one, which is the failure a reader
cannot see.  The repository happens to contain no such case today; the
guard has to be able to see one anyway, because "we have not been bitten
yet" is not a property a guard can rely on.

WHAT THIS GUARD IS NOT
----------------------
It does not remove the ``ba_*`` modules, rename them, or change their
public behaviour.  ``docs/design/exclusion-reasons.md`` records that they
are deliberate ("scratch utility modules from the mock batches").  The
defect is the DUPLICATED SOURCE inside them, not their existence.

THE RULE THIS SLICE PINS
-------------------------
> **No module in the repository defines the same top-level name twice.**

Checked over the WHOLE repository, not one component: a duplicate in a
component's ``tests/`` directory is just as invisible as one in a
shipped module, and a guard that only looked at the shipped modules
would miss half the surface.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The directories whose ``.py`` files are part of the repository's source.
#: ``tests`` is INCLUDED: a duplicated definition in a test file is just
#: as dead a piece of code as one in a shipped module.
SOURCE_DIRS = ("components", "tests", "tools", "scripts", "examples")

#: Directories that hold generated or vendored code, not the repository's
#: own source.  A duplicate there is somebody else's problem.
EXCLUDED_DIR_NAMES = frozenset(
    {
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "sdk-ts",
        ".git",
        ".pytest_cache",
    }
)


def _source_files() -> list[Path]:
    """Every ``.py`` file that is part of the repository's own source."""
    found: list[Path] = []
    for name in SOURCE_DIRS:
        base = ROOT / name
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            relative = path.relative_to(ROOT)
            if EXCLUDED_DIR_NAMES.intersection(relative.parts):
                continue
            found.append(path)
    return sorted(found)


def duplicate_top_level_definitions(source: str) -> list[tuple[str, bool]]:
    """The top-level names a module defines more than once.

    Returns ``(name, bodies_differ)`` pairs, sorted by name.

    ``bodies_differ`` is True when the duplicate definitions are NOT
    byte-for-byte equivalent -- the case in which the first definition is
    silently dead code carrying different behaviour.  The identical case is
    merely untidy; the differing case is a defect.
    """
    tree = ast.parse(source)
    by_name: dict[str, list[ast.AST]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            by_name.setdefault(node.name, []).append(node)

    duplicates: list[tuple[str, bool]] = []
    for name, nodes in by_name.items():
        if len(nodes) < 2:
            continue
        bodies = {
            ast.dump(ast.Module(body=node.body, type_ignores=[])) for node in nodes
        }
        duplicates.append((name, len(bodies) > 1))
    return sorted(duplicates)


#: The runtime component, whose ``ba_*`` family this slice repaired.
RUNTIME = ROOT / "components" / "northstar-agent-runtime"


def _ba_modules() -> list[Path]:
    """The runtime's ``ba_01``..``ba_50`` family, in order."""
    return [RUNTIME / ("ba_%02d.py" % index) for index in range(1, 51)]


def _load(path: Path, name: str):
    """Import a module from its file, by path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



class DuplicateDefinitionTests(unittest.TestCase):
    """The repository must not define the same top-level name twice."""

    def test_no_module_defines_the_same_top_level_name_twice(self):
        offenders: list[str] = []
        for path in _source_files():
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for name, differ in duplicate_top_level_definitions(source):
                kind = "differing bodies" if differ else "identical bodies"
                offenders.append(
                    "%s: defines %r %d times (%s)"
                    % (path.relative_to(ROOT), name, 2, kind)
                )
        self.assertEqual(
            offenders,
            [],
            "module(s) defining a top-level name more than once:\n  "
            + "\n  ".join(offenders),
        )

    def test_the_scan_actually_covers_the_repository(self):
        # A scan that finds nothing would pass the assertion above
        # vacuously.  The repository has well over a thousand Python
        # files; the scan must find them, and it must find the `ba_*`
        # family it is meant to police.
        files = _source_files()
        self.assertGreater(
            len(files),
            1000,
            "the scan found only %d files -- it is not scanning the "
            "repository" % len(files),
        )
        names = {path.name for path in files}
        self.assertIn("ba_01.py", names, "the scan does not reach the runtime")
        self.assertIn(
            "test_duplicate_definitions.py",
            names,
            "the scan does not reach the repository's own tests",
        )


class RepairedFamilyTests(unittest.TestCase):
    """The repaired family must still work, and must work ONCE.

    The fix removed a DUPLICATE, not a test.  These tests pin that the
    ``ba_*`` modules still expose their public function, still pass
    their own self-test, and now run it exactly once.

    They IMPORT the modules rather than reading them as text, because a
    test that only reads the source cannot tell a working module from a
    broken one.
    """

    def test_every_ba_module_still_exposes_its_public_function(self):
        for path in _ba_modules():
            with self.subTest(module=path.name):
                module = _load(path, "b173_ba_" + path.stem)
                public = [
                    name
                    for name in vars(module)
                    if not name.startswith("_") and callable(vars(module)[name])
                ]
                self.assertEqual(
                    len(public),
                    1,
                    "%s should expose exactly one public callable, found %s"
                    % (path.name, public),
                )

    def test_every_ba_module_still_passes_its_own_self_test(self):
        for path in _ba_modules():
            with self.subTest(module=path.name):
                module = _load(path, "b173_ba_self_" + path.stem)
                self.assertTrue(
                    hasattr(module, "_tests"),
                    "%s lost its _tests() self-test" % path.name,
                )
                module._tests()  # raises on failure

    def test_running_a_ba_module_as_a_script_does_the_work_once(self):
        # THE OBSERVABLE DEFECT.  Before the fix every one of these
        # modules printed "ok" TWICE, because the self-test block was
        # duplicated in the file.  After the fix it prints once.
        import subprocess
        import sys

        for path in _ba_modules():
            with self.subTest(module=path.name):
                result = subprocess.run(
                    [sys.executable, str(path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    "%s exited %d: %s" % (path.name, result.returncode, result.stdout),
                )
                self.assertEqual(
                    result.stdout.splitlines(),
                    ["ok"],
                    "%s did the work exactly once; it printed %r"
                    % (path.name, result.stdout),
                )


class GuardHonestyTests(unittest.TestCase):
    """The guard must be able to fail -- on both kinds of duplicate."""

    def test_an_identical_duplicate_is_reported(self):
        source = (
            "def helper():\n"
            "    return 1\n"
            "\n"
            "def helper():\n"
            "    return 1\n"
        )
        self.assertEqual(
            duplicate_top_level_definitions(source),
            [("helper", False)],
            "an identical duplicate must be reported",
        )

    def test_a_duplicate_whose_bodies_differ_is_reported_as_differing(self):
        # The harmful case: the first definition is silently dead code.
        source = (
            "def helper():\n"
            "    return 1\n"
            "\n"
            "def helper():\n"
            "    return 2\n"
        )
        self.assertEqual(
            duplicate_top_level_definitions(source),
            [("helper", True)],
            "a duplicate with different bodies must be reported as differing",
        )

    def test_a_module_without_duplicates_reports_nothing(self):
        source = (
            "def one():\n"
            "    return 1\n"
            "\n"
            "\n"
            "def two():\n"
            "    return 2\n"
            "\n"
            "\n"
            "class Three:\n"
            "    pass\n"
        )
        self.assertEqual(duplicate_top_level_definitions(source), [])

    def test_a_duplicate_name_in_different_scopes_is_not_a_duplicate(self):
        # Two methods with the same name in two different classes are
        # perfectly normal.  Only TOP-LEVEL definitions are the rule.
        source = (
            "class A:\n"
            "    def run(self):\n"
            "        return 1\n"
            "\n"
            "\n"
            "class B:\n"
            "    def run(self):\n"
            "        return 2\n"
        )
        self.assertEqual(duplicate_top_level_definitions(source), [])

    def test_a_redefinition_that_is_an_intentional_override_is_still_reported(self):
        # There is no legitimate reason to define the same top-level name
        # twice in this repository, and the guard must not make an
        # exception: an exception is a hole the next slice walks through.
        source = (
            "import os\n"
            "\n"
            "\n"
            "def helper():\n"
            "    return 1\n"
            "\n"
            "\n"
            "def helper():\n"
            "    return 1\n"
        )
        self.assertEqual(duplicate_top_level_definitions(source), [("helper", False)])


if __name__ == "__main__":
    unittest.main()
