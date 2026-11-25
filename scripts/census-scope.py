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

A STATIC import is not the only way a suite reaches a module
-------------------------------------------------------------------
Measured 2026-11-25: **519** of the runtime's suites do NOT import
their module.  They load it BY FILE PATH, because the module is not
importable in isolation and the suite needs it standalone::

    def _load(name):
        spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    ap = _load("annotation_pin")

A static-only index therefore returned the EMPTY scope for those
modules, and the census printed ``MUTANT SKIP: no test file exercises
annotation_pin``.  **121 of the 270 rows** in
``docs/baseline/mutant-census/census-v3.txt`` name such a module, so
121 of 270 measurements were SKIPped -- and a SKIP is invisible: the
artifact still carries a number for the row, measured at a narrower
scope, and the row looks like a measurement.

So the scope is the union of the suites that reach the module BY ANY
MEANS: a static import, or one of the dynamic-load shapes read by
:func:`_dynamic_module_names`.  Docstrings are excluded from both --
a docstring that names a module is documentation, not a load.

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
import re
import sys
from pathlib import Path

#: The parsed import index, per root.  Built once, then looked up.
_INDEX_CACHE: dict[str, dict[str, list[str]]] = {}

#: A plain module base name.
_MODULE_STEM = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


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


def _docstring_constants(tree: ast.Module) -> set[int]:
    """The ids of the string constants that are DOCSTRINGS.

    A docstring is not a reference to anything.  ``test_annotation_pin``'s
    module docstring names ``annotation_pin``, and so does the census
    artifact's prose -- but a docstring is documentation, not a load.
    """
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                ids.add(id(body[0].value))
    return ids


def _fstring_path_var(node: ast.AST) -> str | None:
    """``f"{name}.py"`` -> ``"name"``; ``None`` for any other shape.

    The house loader in 519 of the runtime's suites is::

        def _load(name):
            spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")

    The path is built from the NAME, so the reference cannot be read off
    the f-string alone -- the CALL SITE carries the name.

    The f-string is usually wrapped in a path join (``RUNTIME / f"..."``),
    so the BinOp is unwrapped first.  The join's other side is the
    directory, so it carries no name.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        for side in (node.left, node.right):
            var = _fstring_path_var(side)
            if var:
                return var
        return None
    if not isinstance(node, ast.JoinedStr):
        return None
    parts: list[tuple[str, str]] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(("lit", value.value))
        elif (isinstance(value, ast.FormattedValue)
              and isinstance(value.value, ast.Name)):
            parts.append(("var", value.value.id))
        else:
            return None
    # The suffix may be quoted either way -- the runtime's suites use
    # both `f"{name}.py"` and `f'{name}.py'`, and a resolver that reads
    # only one of them misses half the runtime.
    #
    # The template may also carry a leading empty literal (`f"{name}.py"`)
    # or not (`f'{name}.py'` parses as just the variable and the suffix),
    # so both arities are accepted.
    if len(parts) == 3 and parts[0] == ("lit", "") and parts[1][0] == "var" \
            and parts[2] == ("lit", ".py"):
        return parts[1][1]
    if len(parts) == 2 and parts[0][0] == "var" and parts[1] == ("lit", ".py"):
        return parts[0][1]
    return None


def _dynamic_module_names(tree: ast.Module, docstrings: set[int]) -> set[str]:
    """The module names a file loads DYNAMICALLY, by path.

    A STATIC import index is not enough.  Measured 2026-11-25: **519**
    of the runtime's suites load their module by file path rather than
    by import statement, and **121 of the 270 rows** in
    ``docs/baseline/mutant-census/census-v3.txt`` name a module that no
    suite imports statically.  For those rows the scope resolver returned
    the EMPTY scope, and the census printed
    ``MUTANT SKIP: no test file exercises <module>`` -- so **121 of 270
    measurements were silently skipped**, and the SKIP looked like a
    deliberate scope decision.

    The shapes this recognises, all measured against the runtime's own
    suites:

    1. ``spec_from_file_location(<literal name>, ...)``
    2. the house loader: a helper whose body holds
       ``spec_from_file_location(name, ... / f"{name}.py")``, called with
       a literal module name
    3. ``types.ModuleType("<literal name>")`` followed by ``exec``
    4. ``sys.modules["<literal name>"] = ...``
    5. a path constant of the shape ``... / "<name>.py"``

    Every literal must be a plain module base name, and docstrings are
    excluded (see :func:`_docstring_constants`).
    """
    names: set[str] = set()

    def _plain(value: str) -> bool:
        return bool(_MODULE_STEM.fullmatch(value.strip()))

    # (2) the house loader: find the helpers and their literal arguments.
    helper_var: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for call in ast.walk(node):
                if (isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr == "spec_from_file_location"):
                    for arg in call.args:
                        var = _fstring_path_var(arg)
                        if var:
                            helper_var[node.name] = var
    helper_args: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in helper_var):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if _plain(arg.value):
                        helper_args.setdefault(node.func.id, set()).add(arg.value)
    for args in helper_args.values():
        names |= args

    for node in ast.walk(tree):
        # (1) spec_from_file_location("<name>", ...)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "spec_from_file_location"):
            for arg in node.args:
                if (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                        and id(arg) not in docstrings and _plain(arg.value)):
                    names.add(arg.value.strip())
        # (3) types.ModuleType("<name>")
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "ModuleType"):
            for arg in node.args:
                if (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                        and id(arg) not in docstrings and _plain(arg.value)):
                    names.add(arg.value.strip())
        # (4) sys.modules["<name>"] = ...
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Subscript)
                        and isinstance(target.value, ast.Attribute)
                        and target.value.attr == "modules"):
                    key = target.slice
                    if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                            and id(key) not in docstrings and _plain(key.value)):
                        names.add(key.value.strip())
        # (5) a path constant: ... / "<name>.py"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            for side in (node.left, node.right):
                if (isinstance(side, ast.Constant) and isinstance(side.value, str)
                        and id(side) not in docstrings):
                    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\.py",
                                         side.value.strip())
                    if match:
                        names.add(match.group(1))
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
        names = _module_names(tree)
        # A STATIC import is not the only way a suite reaches a module.
        # 519 of the runtime's suites load theirs by file path, and for
        # the 121 census rows whose module no suite imports statically,
        # leaving these out made the scope EMPTY -- so the census SKIPped
        # the row and the SKIP looked deliberate.  See
        # :func:`_dynamic_module_names`.
        names |= _dynamic_module_names(tree, _docstring_constants(tree))
        for name in names:
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
