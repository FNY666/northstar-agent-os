"""The runtime's ``py-modules`` list must be sorted and free of duplicates.

THE DEFECT, MEASURED (2026-11-17)
---------------------------------
``[tool.setuptools] py-modules`` is the array that says which flat modules
``pip install .`` puts on the path.  The runtime's array was neither sorted
nor deduplicated:

    $ python3 - <<'PY'
    ... # parse components/northstar-agent-runtime/pyproject.toml
    ... print(len(modules), len(set(modules)))
    PY
    1663 1613

    1663 entries, 1613 distinct names: **50 names appear twice**.
    Every one of the 50 is a ``ba_*`` module -- the same scratch-utility
    family the ``duplicate-definition`` slice repaired.  The second copy of
    the family sits at the very END of the array, after ``zw_remove``:

        $ grep -n '"ba_01"' pyproject.toml
        359:    "ba_01", "ba_02", "ba_03", "ba_04",
        1626:    "ba_01",

    And the array is not sorted: there are **9 inversions**, pairs where a
    name is followed by a name that sorts before it:

        approval_rules > approval_chain_time
        defensive_agent > crescendo_probe
        graphql_gateway > grant_pin_ledger
        memory_integrity > memory_admission
        planted_fault > planner_budget_combo
        runtime_evidence > runtime_defense_01
        shutdownability > shutdown_unwind
        tool_system_30 > tool_failure
        zw_remove > ba_01

WHY IT SURVIVED
---------------
The repository has a guard for exactly this rule -- but only for the
**interop** component:

    tests/test_component_packaging_closure.py::
        test_the_py_modules_list_is_sorted_and_deduplicated

It reads ``components/northstar-agent-interop/pyproject.toml`` and never
looks at the runtime's.  The runtime component -- the largest, with 1663
entries and by far the most duplication -- had no such guard.

Meanwhile the runtime's own ``tests/test_module_layout.py`` reads the same
array with ``set(...)``:

    declared = set(pyproject["tool"]["setuptools"]["py-modules"])

which throws away exactly the information this defect is about.  A set
cannot hold a duplicate, so every check built on it is blind to one.

THE RULE THIS SLICE PINS
-------------------------
> **The runtime's ``py-modules`` list is sorted and has no duplicate
> entries.**

Sorted so that adding a module is a ONE-LINE diff instead of a reshuffle,
and deduplicated so the array says what it means to say.

WHAT DOES NOT CHANGE
--------------------
The **installed surface is unchanged**.  setuptools deduplicates the list
when it builds the wheel, so the wheel this slice's fix produces carries
exactly the same modules as the wheel it replaces.  That is asserted
below: the wheel's module set must equal the declared set, and the wheel
must carry no duplicated entry.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
PYPROJECT = COMPONENT / "pyproject.toml"


def declared_modules() -> list[str]:
    """The ``py-modules`` array, in the order it appears in the file."""
    import tomllib

    pyproject = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return list(pyproject["tool"]["setuptools"]["py-modules"])


def _build_wheel(tmp: Path) -> Path:
    """Build the runtime's wheel for real.

    Reading ``pyproject.toml`` proves only what somebody wrote; the wheel
    is the artifact setuptools actually ships.

    The build runs OUT OF TREE.  setuptools writes its scratch tree
    (``build/``, ``<name>.egg-info/``) into the source directory it is
    handed, does not clean it between builds, and a second build then dies
    with ``Errno 17: File exists`` on the first build's ``.dist-info``.  So
    the sources are copied to a scratch directory first and the wheel is
    built there: the artifact is then a function of the source and nothing
    else, and the checkout is untouched.
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


class PyModulesListTests(unittest.TestCase):
    """The rule, stated as the array's own shape."""

    def test_the_py_modules_list_is_sorted(self):
        modules = declared_modules()
        self.assertEqual(
            sorted(modules),
            modules,
            "the py-modules list must stay sorted; the first out-of-order "
            "pair is %r" % (_first_inversion(modules),),
        )

    def test_the_py_modules_list_has_no_duplicates(self):
        modules = declared_modules()
        duplicates = sorted({name for name in modules if modules.count(name) > 1})
        self.assertEqual(
            duplicates,
            [],
            "duplicate entries in py-modules: %s" % duplicates,
        )

    def test_the_list_has_no_duplicate_lines_in_the_file_either(self):
        # The TOML array is parsed as a list, so a repeated NAME is visible
        # above.  This checks the file itself has no repeated line, which
        # would catch a duplicate introduced by a bad edit that TOML still
        # parses (and which a merge conflict marker could leave behind).
        lines = [
            line.strip()
            for line in PYPROJECT.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith('"')
        ]
        duplicates = sorted({line for line in lines if lines.count(line) > 1})
        self.assertEqual(duplicates, [], "repeated entries: %s" % duplicates)

    def test_the_list_is_not_empty_and_covers_the_component(self):
        # A guard that passes because the array became empty would be
        # worthless.  The runtime has 1613 flat modules; the array must
        # still declare them.
        modules = declared_modules()
        self.assertGreater(len(modules), 1500, "the array shrank to %d" % len(modules))
        on_disk = {
            path.stem
            for path in COMPONENT.glob("*.py")
            if path.name not in {"setup.py", "conftest.py"}
            and not path.name.startswith("test_")
        }
        self.assertEqual(
            sorted(on_disk - set(modules)),
            [],
            "module(s) on disk but not declared: %s" % sorted(on_disk - set(modules)),
        )


class InstalledSurfaceTests(unittest.TestCase):
    """The fix must not change WHAT SHIPS -- only how it is written down.

    setuptools deduplicates ``py-modules`` when it builds the wheel, so
    the duplicate entries were harmless to the artifact.  That is exactly
    why the defect could sit there unnoticed: the wheel was already
    correct.  This class pins that the repair did not change the artifact,
    so the cleanup stays a cleanup.
    """

    def test_the_wheel_ships_exactly_the_declared_modules(self):
        with tempfile.TemporaryDirectory(prefix="b173-pymod-") as tmp:
            wheel = _build_wheel(Path(tmp))
            with zipfile.ZipFile(wheel) as archive:
                entries = [
                    name
                    for name in archive.namelist()
                    if name.endswith(".py")
                ]
        # The wheel's paths are relative to the install root, so a package
        # member is `providers/foo.py` and a flat module is `foo.py`.
        # Compare on the PATH, not on the stem: the stem would collapse
        # `providers/__init__.py`, `tools/__init__.py` and
        # `policy/__init__.py` to the same `__init__` and hide three of the
        # shipped modules.
        flat_shipped = {Path(name).stem for name in entries if "/" not in name}
        package_shipped = {name for name in entries if "/" in name}
        declared = set(declared_modules())
        self.assertEqual(
            sorted(declared - flat_shipped),
            [],
            "module(s) declared but not in the wheel: %s"
            % sorted(declared - flat_shipped),
        )
        # The flat modules are a SUBSET of the shipped surface; the
        # package members (`providers.*`, `tools.*`, `policy.*`) ship too.
        self.assertEqual(
            sorted(flat_shipped - declared),
            [],
            "flat module(s) in the wheel that no list declares: %s"
            % sorted(flat_shipped - declared),
        )
        self.assertTrue(
            package_shipped,
            "the wheel ships no package members; the flat list is only "
            "part of the surface",
        )
        self.assertEqual(len(entries), 1638, sorted(entries)[:5])

    def test_the_wheel_has_no_duplicated_entries(self):
        with tempfile.TemporaryDirectory(prefix="b173-pymod-dup-") as tmp:
            wheel = _build_wheel(Path(tmp))
            with zipfile.ZipFile(wheel) as archive:
                names = archive.namelist()
        py_entries = [name for name in names if name.endswith(".py")]
        self.assertEqual(
            len(py_entries),
            len(set(py_entries)),
            "the wheel carries a duplicated entry: %s"
            % sorted({n for n in py_entries if py_entries.count(n) > 1}),
        )


class GuardHonestyTests(unittest.TestCase):
    """The guard must be able to fail."""

    def _sorted_check(self, modules: list[str]) -> bool:
        return sorted(modules) == list(modules)

    def test_an_unsorted_list_is_detected(self):
        modules = ["b_module", "a_module"]
        self.assertFalse(self._sorted_check(modules))

    def test_a_duplicate_is_detected(self):
        modules = ["a_module", "a_module"]
        self.assertNotEqual(len(modules), len(set(modules)))

    def test_a_sorted_deduplicated_list_passes_both_checks(self):
        modules = ["a_module", "b_module"]
        self.assertTrue(self._sorted_check(modules))
        self.assertEqual(len(modules), len(set(modules)))


def _first_inversion(modules: list[str]) -> tuple[str, str] | None:
    """The first adjacent pair that is out of order."""
    for index in range(len(modules) - 1):
        if modules[index] > modules[index + 1]:
            return (modules[index], modules[index + 1])
    return None


if __name__ == "__main__":
    unittest.main()
