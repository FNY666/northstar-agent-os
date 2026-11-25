#!/usr/bin/env python3
"""Resolve a module's TEST SCOPE: the union of every suite that references it.

A module's real coverage is the union of every suite that references it.
Pairing a module with only its OWN test file understates that coverage and
produces false survivors -- mutants that a sibling suite would have caught
are reported as SURVIVED.

    job_queue.py   its own suite alone       -> 42 survivors (measured)
    job_queue.py   union of the four suites  -> 13 survivors (measured)

The four suites that reference ``job_queue`` are ``test_job_queue``,
``test_leased_task_claim``, ``test_refusal_hold`` and
``test_refusal_hold_queue_wiring``.  Two more files -- ``test_graph_database``
and ``test_status_page`` -- mention the module, but only in PROSE: they
quote ``job_queue.py``'s rules in a comment.  A scope that counted those
would be measuring a suite that does not exercise the module at all.

So "references" here means a REAL import, read from the AST:

  * ``import job_queue``
  * ``from job_queue import JobQueue``
  * ``from job_queue import (...)``
  * ``from . import job_queue`` / ``from .job_queue import X`` (relative)

A mention inside a comment or a docstring is not an import and does not
count.  That distinction is the whole point: the earlier rule was a
``grep`` over the file, and ``grep`` cannot tell a comment from an import.

Usage::

    python3 scripts/census-scope.py --root <runtime dir> <module-base>...
    python3 scripts/census-scope.py --root <runtime dir> --json <module-base>

Prints one line per module::

    job_queue: test_job_queue,test_leased_task_claim,test_refusal_hold,test_refusal_hold_queue_wiring

The module's OWN suite comes first, then the referencing suites in
alphabetical order -- the order is stable so a census log is comparable
between runs.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

#: The parsed import index, per root.  Built once, then looked up.
_INDEX_CACHE: dict[str, dict[str, list[str]]] = {}


def _module_names(tree: ast.Module) -> set[str]:
    """The module names a file genuinely imports."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # a relative import: `from . import x` / `from .x import y`
                if node.module:
                    names.add(node.module.split(".")[0])
                for alias in node.names:
                    names.add(alias.name.split(".")[0])
            elif node.module:
                names.add(node.module.split(".")[0])
    return names


def _import_index(root: Path) -> dict[str, list[str]]:
    """``{module name: [suite stems that import it]}`` over ``root/tests``.

    Every test file is parsed ONCE, not once per module asked about.
    The per-module version re-parsed all 1,554 test files for each of
    the runtime's 1,619 modules -- 2.5 million parses, which took
    minutes.  The index is built once and then answers every question
    by lookup.

    A file that does not parse contributes nothing: it cannot be shown
    to import the module, and a suite that cannot be parsed is not a
    suite that exercises anything.

    The index is CACHED per root, so asking about many modules in one
    process parses the tree once.
    """
    key = str(root.resolve())
    cached = _INDEX_CACHE.get(key)
    if cached is not None:
        return cached
    tests_dir = root / "tests"
    index: dict[str, list[str]] = {}
    if not tests_dir.is_dir():
        _INDEX_CACHE[key] = index
        return index
    for path in sorted(tests_dir.glob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for name in _module_names(tree):
            index.setdefault(name, []).append(path.stem)
    _INDEX_CACHE[key] = index
    return index


def referencing_suites(root: Path, module_base: str) -> list[str]:
    """Every suite in ``root/tests`` that genuinely imports the module.

    The module's OWN suite is included (it imports it by construction, and
    it is listed FIRST because it is the one that exists to cover it).
    """
    found = list(_import_index(root).get(module_base, []))
    own = f"test_{module_base}"
    if own in found:
        found.remove(own)
        found.insert(0, own)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=str(
            Path(__file__).resolve().parents[1]
            / "components"
            / "northstar-agent-runtime"
        ),
        help="the runtime directory holding tests/",
    )
    parser.add_argument("--json", action="store_true", help="print JSON only")
    parser.add_argument("modules", nargs="+", help="module base names")
    args = parser.parse_args()

    root = Path(args.root)
    report = {
        base: referencing_suites(root, base) for base in args.modules
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for base in args.modules:
            suites = report[base]
            if not suites:
                print(f"{base}: (no suite references it)", file=sys.stderr)
                continue
            print(f"{base}: {','.join(suites)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
