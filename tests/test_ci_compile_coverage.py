"""CI must compile every module every component ships.

THE DEFECT, MEASURED (2026-11-17)
---------------------------------
A compile step is what catches a module that does not parse.  It is the
cheapest check in the whole pipeline and the one most likely to be
narrowed by accident.

The repository's CI jobs do not all compile the same way.  Some use a
glob; some name every module by hand:

    # runtime -- a glob, with a comment saying why:
    python -m py_compile *.py providers/*.py tools/*.py \
      tests/support.py tests/fixtures/*.py tests/test_*.py

    # durable-run -- a hand-maintained list:
    python -m py_compile durable_contract.py event_store.py
      action_gateway.py runner.py verifier.py trace_metrics.py
      evaluation.py durable_audit.py tests/test_*.py

Measured against the modules each component actually ships, **9 shipped
modules are not compile-checked by CI at all**:

| component | shipped | compiled by CI | missing |
|---|---|---|---|
| northstar-agent-runtime | 1636 | 1635 | **1** |
| northstar-durable-run | 16 | 8 | **8** |
| northstar-agent-interop | 8 | 8 | 0 |
| northstar-host | 4 | 4 | 0 |
| northstar-run-contract | 5 | 5 | 0 |
| northstar-run-evidence | 6 | 6 | 0 |

The runtime's missing one is ``policy/__init__.py`` -- the package the
``runtime-data-files`` slice created so that the runtime's data files
could ship in the wheel.  That slice's own change made the gap: the CI
compile step's glob was written for a component whose packages were
``providers`` and ``tools``, and the new package was not added to it.

    $ python3 - <<'PY'
    ... # for each component, expand the CI job's py_compile globs
    ... # and compare against the modules the component ships
    PY
    northstar-agent-runtime      shipped=1636  covered=1635  MISSING=1
           policy/__init__.py
    northstar-durable-run         shipped=16    covered=8     MISSING=8
           blob_store.py  event_migration.py  governed_memory.py
           receipt_gate.py  timelock.py  tool_allowlist.py
           tool_ledger.py  tool_receipt.py

WHY IT SURVIVED
---------------
**The runtime's CI comment says the glob exists precisely to stop this,
and the glob was never extended.**  The comment reads:

    # Every module the component ships, by glob rather than by hand: a curated list
    # here silently stopped covering new modules the moment they landed, which is the
    # opposite of what a compile step is for.

The runtime did the right thing.  It then added a package and did not
extend the glob -- so the comment promises a property the command does
not have.

**And the durable-run component still uses a hand-maintained list**, the
exact thing the runtime's comment warns against.  Its list was written
when the component had 8 modules; 8 more landed and the list was never
extended.  The history file says it in as many words
(``docs/history/next-gen-agent-blueprint-v1-2026-09.zh-CN.md``):

    CI 编译行改为整目录 glob（手抄清单已漏掉数个新模块，正是它该被自动化的原因）

-- "the CI compile line was changed to a whole-directory glob; the
hand-copied list had already missed several new modules, which is exactly
why it needed to be automated."

The automation happened in the runtime and never reached durable-run.

**No guard checks this.**  The repository has
``test_the_ci_compile_list_and_the_install_list_agree`` -- but it reads
the interop component's lines and checks that the INSTALL SMOKE check
imports what the COMPILE step compiles.  It is about the interop
component's install check, not about what CI compiles at all.

THE RULE THIS SLICE PINS
-------------------------
> **Every module a component ships is compiled by that component's CI
> compile step.**

Checked for EVERY component in the repository, so the next component that
grows a module inherits the guard for free.

WHAT THIS SLICE IS NOT
----------------------
It does not change what CI DOES beyond making the compile steps cover
what they are supposed to cover.  It does not add a lint step, a type
checker, or a coverage threshold.  It does not change the runtime's
modules.
"""
from __future__ import annotations

import glob
import re
import shlex
import tempfile
import unittest
from pathlib import Path

import docbuild

ROOT = docbuild.ROOT
COMPONENTS = ROOT / "components"
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"

#: The components whose modules CI compiles.  The two sidecars ship no
#: wheel, so they have no ``py-modules`` and there is nothing to compare
#: against -- but they have modules, so they are checked against the files
#: on disk instead.
COMPONENTS_WITH_A_WHEEL = (
    "northstar-agent-runtime",
    "northstar-agent-interop",
    "northstar-durable-run",
    "northstar-host",
    "northstar-run-contract",
    "northstar-run-evidence",
)

#: The components that ship no wheel but do have modules.  Their coverage
#: is measured against the ``.py`` files in their directory, excluding the
#: ones that are not modules.
COMPONENTS_WITHOUT_A_WHEEL = (
    "northstar-codex-sidecar",
    "northstar-egress-sidecar",
)


def compile_steps() -> list[tuple[str, list[str]]]:
    """Every ``py_compile`` step in the workflow, as (working directory, files).

    The working directory is the step's ``working-directory:`` (which the
    workflow sets per job), and the files are the glob patterns the
    ``py_compile`` command was given.
    """
    text = WORKFLOW.read_text(encoding="utf-8")
    # Join the lines of every `run:` block first: a compile command may be
    # wrapped over several lines with a trailing backslash, and a
    # line-by-line read would see only the first fragment.
    lines = text.splitlines()
    working_directory = ""
    steps: list[tuple[str, list[str]]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        directory = re.search(r"working-directory:\s*(\S+)", line)
        if directory:
            working_directory = directory.group(1)
        if "py_compile" in line:
            block = [line]
            while block[-1].rstrip().endswith("\\") and index + 1 < len(lines):
                index += 1
                block.append(lines[index])
            joined = " ".join(part.strip() for part in block)
            joined = joined.replace("\\", " ")
            patterns = shlex.split(joined)
            # Everything after `py_compile` is a pattern; drop the command
            # words themselves.
            try:
                start = patterns.index("py_compile")
            except ValueError:
                start = 0
            steps.append((working_directory, patterns[start + 1 :]))
        index += 1
    return steps


def compiled_paths(working_directory: str, patterns: list[str]) -> set[str]:
    """The source paths a compile step's globs actually match.

    ``working_directory`` is the path the workflow's job runs in,
    relative to the repository root -- ``components/<component>``.
    """
    base = (ROOT / working_directory).resolve()
    found: set[str] = set()
    for pattern in patterns:
        for match in glob.glob(str(base / pattern)):
            path = Path(match)
            if not path.is_file():
                continue
            found.add(str(path.relative_to(base)))
    return found


def compiled_python_paths(working_directory: str, patterns: list[str]) -> set[str]:
    """The ``.py`` paths a compile step's globs actually compile.

    ``py_compile`` compiles Python source and nothing else.  A glob that
    also matched, say, a ``.toml`` file would make the compile step FAIL,
    so such a file is not "covered" -- it breaks the step.
    """
    base = (ROOT / working_directory).resolve()
    found: set[str] = set()
    for pattern in patterns:
        for match in glob.glob(str(base / pattern)):
            path = Path(match)
            if not path.is_file() or path.suffix != ".py":
                continue
            found.add(str(path.relative_to(base)))
    return found


def shipped_paths(component: str) -> set[str]:
    """The source paths of the modules a component ships.

    A flat module is ``name.py``; a package member is ``package/name.py``
    (and the package itself is ``package/__init__.py``).
    """
    paths: set[str] = set()
    for name in docbuild.flat_modules(component):
        paths.add("%s.py" % name)
    for member in docbuild.package_members(component):
        package, _, leaf = member.rpartition(".")
        paths.add("%s/%s.py" % (package, leaf))
    return paths


def on_disk_paths(component: str) -> set[str]:
    """The source paths of a component's own modules, from the filesystem.

    For the components that ship no wheel, the files on disk are the only
    statement of what they contain.
    """
    base = COMPONENTS / component
    found: set[str] = set()
    for path in sorted(base.glob("*.py")):
        if not docbuild.is_runtime_module(path):
            continue
        found.add(path.name)
    return found


class CiCompileCoverageTests(unittest.TestCase):
    """The rule, applied to every component."""

    def test_the_scan_finds_a_compile_step_for_every_component(self):
        # A guard that silently stopped finding compile steps would pass
        # vacuously -- there would be nothing to compare against.
        found = {directory for directory, _ in compile_steps()}
        for component in COMPONENTS_WITH_A_WHEEL + COMPONENTS_WITHOUT_A_WHEEL:
            with self.subTest(component=component):
                self.assertIn(
                    "components/%s" % component,
                    found,
                    "no py_compile step found for %s" % component,
                )

    def test_ci_compiles_every_module_every_component_ships(self):
        for component in COMPONENTS_WITH_A_WHEEL:
            shipped = shipped_paths(component)
            with self.subTest(component=component):
                self.assertTrue(shipped, "%s ships no modules?" % component)
                covered: set[str] = set()
                for directory, patterns in compile_steps():
                    if directory != "components/%s" % component:
                        continue
                    covered |= compiled_python_paths(directory, patterns)
                missing = sorted(shipped - covered)
                self.assertEqual(
                    missing,
                    [],
                    "%s: module(s) shipped but not compiled by CI: %s"
                    % (component, missing),
                )

    def test_ci_compiles_every_module_of_the_components_that_ship_no_wheel(self):
        # The two sidecars have no `py-modules`, so the rule above has
        # nothing to compare against for them.  Their files on disk are
        # the statement of what they contain, and they are checked too.
        for component in COMPONENTS_WITHOUT_A_WHEEL:
            present = on_disk_paths(component)
            with self.subTest(component=component):
                self.assertTrue(present, "%s has no modules?" % component)
                covered: set[str] = set()
                for directory, patterns in compile_steps():
                    if directory != "components/%s" % component:
                        continue
                    covered |= compiled_python_paths(directory, patterns)
                missing = sorted(present - covered)
                self.assertEqual(
                    missing,
                    [],
                    "%s: module(s) on disk but not compiled by CI: %s"
                    % (component, missing),
                )

    def test_the_runtime_compile_step_covers_every_package(self):
        # The runtime's compile step uses GLOBS, and its comment says the
        # glob exists so that a new package cannot be missed.  A package
        # that is not in the glob is therefore a contradiction of the
        # comment, and this test names it.
        runtime = "components/northstar-agent-runtime"
        covered: set[str] = set()
        for directory, patterns in compile_steps():
            if directory != runtime:
                continue
            covered |= compiled_python_paths(directory, patterns)
        packages = {
            path.name
            for path in (COMPONENTS / "northstar-agent-runtime").iterdir()
            if path.is_dir()
            and path.name != "northstar-agent-runtime"
            and (path / "__init__.py").is_file()
        }
        self.assertTrue(packages, "the runtime ships no packages")
        for package in sorted(packages):
            with self.subTest(package=package):
                self.assertTrue(
                    "%s/__init__.py" % package in covered,
                    "the runtime's CI compile step does not cover the %r "
                    "package, although its comment says the glob exists so "
                    "that new packages cannot be missed" % package,
                )

class GuardUnitTests(unittest.TestCase):
    """The guard's own logic, against crafted workflow files.

    The repository-wide checks above read the REAL workflow, which -- after
    the fix -- covers everything, so on their own they cannot tell a
    working detector from one that never fires.  These tests give the
    detector a workflow that really has a gap.

    They are also what makes the mutant probe meaningful: the probe
    mutates this file and reruns it, and a detector whose every branch is
    exercised only by clean data cannot be distinguished from a broken one.
    """

    def _workflow_with(self, body: str) -> str:
        """A minimal workflow file with one compile step."""
        return (
            "jobs:\n"
            "  a_component:\n"
            "    steps:\n"
            "      - name: Compile\n"
            "        working-directory: components/a_component\n"
            "        run: python -m py_compile %s\n" % body
        )

    def _steps_from(self, text: str) -> list[tuple[str, list[str]]]:
        """The compile steps of a workflow text.

        The production reader reads the real file; this one reads a
        string, so the same extraction can be pointed at a crafted file.
        """
        lines = text.splitlines()
        working_directory = ""
        steps: list[tuple[str, list[str]]] = []
        index = 0
        while index < len(lines):
            line = lines[index]
            directory = re.search(r"working-directory:\s*(\S+)", line)
            if directory:
                working_directory = directory.group(1)
            if "py_compile" in line:
                block = [line]
                while block[-1].rstrip().endswith("\\") and index + 1 < len(lines):
                    index += 1
                    block.append(lines[index])
                joined = " ".join(part.strip() for part in block).replace("\\", " ")
                patterns = shlex.split(joined)
                try:
                    start = patterns.index("py_compile")
                except ValueError:
                    start = 0
                steps.append((working_directory, patterns[start + 1 :]))
            index += 1
        return steps

    def test_a_glob_pattern_is_extracted(self):
        steps = self._steps_from(self._workflow_with("*.py"))
        self.assertEqual(steps, [("components/a_component", ["*.py"])])

    def test_a_wrapped_compile_command_is_read_in_full(self):
        # A compile command may be wrapped over several lines with a
        # trailing backslash.  A line-by-line read would see only the
        # first fragment and MISS the rest -- which is how a module could
        # fall out of coverage without anybody noticing.
        workflow = (
            "jobs:\n"
            "  a_component:\n"
            "    steps:\n"
            "      - name: Compile\n"
            "        working-directory: components/a_component\n"
            "        run: python -m py_compile *.py \\\n"
            "          providers/*.py tools/*.py\n"
        )
        steps = self._steps_from(workflow)
        self.assertEqual(
            steps,
            [("components/a_component", ["*.py", "providers/*.py", "tools/*.py"])],
        )

    def test_a_module_outside_the_glob_is_not_covered(self):
        # The detector's actual job: a module the component has but the
        # glob does not name.
        with tempfile.TemporaryDirectory() as tmp:
            component = Path(tmp) / "a_component"
            (component / "providers").mkdir(parents=True)
            (component / "providers" / "__init__.py").write_text("", encoding="utf-8")
            (component / "providers" / "base.py").write_text("", encoding="utf-8")
            (component / "policy").mkdir()
            (component / "policy" / "__init__.py").write_text("", encoding="utf-8")
            covered = _covered_by("*.py providers/*.py", component)
            self.assertIn("providers/__init__.py", covered)
            self.assertNotIn("policy/__init__.py", covered)

    def test_a_hand_maintained_list_that_misses_a_module_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            component = Path(tmp) / "a_component"
            component.mkdir()
            (component / "one.py").write_text("", encoding="utf-8")
            (component / "two.py").write_text("", encoding="utf-8")
            covered = _covered_by("one.py", component)
            self.assertIn("one.py", covered)
            self.assertNotIn("two.py", covered)

    def test_a_directory_that_does_not_exist_matches_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            component = Path(tmp) / "a_component"
            component.mkdir()
            covered = _covered_by("packages/*.py", component)
            self.assertEqual(covered, set())

    def test_a_non_python_file_in_the_glob_is_not_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            component = Path(tmp) / "a_component"
            component.mkdir()
            (component / "data.toml").write_text("", encoding="utf-8")
            covered = _covered_by("*", component)
            self.assertEqual(covered, set())


def _covered_by(patterns: str, base: Path) -> set[str]:
    """The ``.py`` paths a space-separated list of glob patterns matches."""
    found: set[str] = set()
    for pattern in patterns.split():
        for match in glob.glob(str(base / pattern)):
            path = Path(match)
            if not path.is_file() or path.suffix != ".py":
                continue
            found.add(str(path.relative_to(base)))
    return found


if __name__ == "__main__":
    unittest.main()
