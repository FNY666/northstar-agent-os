"""What the repository's CI actually compiles.

This module holds the LOGIC; the test that uses it is
``tests/test_ci_compile_coverage.py``.

WHY A MODULE AND NOT A TEST
---------------------------
The mutant probe mutates a module and reruns the slice's tests, so the
logic has to live in a module the probe can reach.  A test file is not a
module the probe will mutate -- it is excluded by name -- so a guard
whose logic lives entirely inside a test file cannot be mutation-probed
at all.

The same reasoning put the ``py-modules`` logic in
``tests/py_modules_guard.py``.

WHAT THIS MODELS
----------------
A compile step is what catches a module that does not parse.  It is the
cheapest check in the pipeline and the one most likely to be narrowed by
accident.  The repository's CI jobs do not all compile the same way:

    # runtime -- a glob, with a comment saying why:
    python -m py_compile *.py providers/*.py tools/*.py \\
      tests/support.py tests/fixtures/*.py tests/test_*.py

    # durable-run -- a hand-maintained list:
    python -m py_compile durable_contract.py event_store.py \\
      action_gateway.py runner.py verifier.py trace_metrics.py \\
      evaluation.py durable_audit.py tests/test_*.py

So "what does CI compile" is not a fixed list -- it is a question about a
YAML file, and this module is the model of that question.
"""
from __future__ import annotations

import glob
import re
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / "components"
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"


def compile_steps(text: str | None = None) -> list[tuple[str, list[str]]]:
    """Every ``py_compile`` step in a workflow, as (working directory, patterns).

    The working directory is the step's ``working-directory:`` (which the
    workflow sets per job), and the patterns are the glob patterns the
    ``py_compile`` command was given.

    A compile command may be wrapped over several lines with a trailing
    backslash, so the lines of a block are joined before the command is
    parsed.  A line-by-line read would see only the first fragment and
    MISS the rest -- which is how a module could fall out of coverage
    without anybody noticing.

    ``text`` defaults to the repository's real workflow; the tests pass
    crafted workflows to exercise the parser.
    """
    if text is None:
        text = WORKFLOW.read_text(encoding="utf-8")
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


def matched_paths(base: Path, patterns: list[str]) -> set[str]:
    """The paths a list of glob patterns matches under ``base``.

    Only ``.py`` files count.  ``py_compile`` compiles Python source and
    nothing else: a glob that also matched, say, a ``.toml`` file would
    make the compile step FAIL, so such a file is not "covered" -- it
    breaks the step.
    """
    found: set[str] = set()
    for pattern in patterns:
        for match in glob.glob(str(base / pattern)):
            path = Path(match)
            if not path.is_file() or path.suffix != ".py":
                continue
            found.add(str(path.relative_to(base)))
    return found


def compiled_paths(working_directory: str, patterns: list[str]) -> set[str]:
    """The ``.py`` paths a compile step's globs actually compile.

    ``working_directory`` is the path the workflow's job runs in,
    relative to the repository root -- ``components/<component>``.
    """
    return matched_paths((ROOT / working_directory).resolve(), patterns)


def covered_for(component: str, steps: list[tuple[str, list[str]]]) -> set[str]:
    """The paths CI compiles for one component, across all of its steps."""
    covered: set[str] = set()
    for directory, patterns in steps:
        if directory != "components/%s" % component:
            continue
        covered |= compiled_paths(directory, patterns)
    return covered
