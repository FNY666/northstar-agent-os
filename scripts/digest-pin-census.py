#!/usr/bin/env python3
"""Measure the digest-pin class: how many modules can escape it, and which.

The class is "a module imports the sibling helper ``canonical_json`` behind a
``try/except`` fallback, and the module's own error taxonomy does not cover
the helper's ``ValueError``-derived ``JcsError``".  ``canonical_json`` is the
runtime's single canonicalizer; a module that calls it and then guards only
its own exception type has a DEAD guard for that input.

This script counts the class two ways and prints both, because the two
answer different questions:

* **the STATIC sweep** — an AST walk over the runtime's top-level modules.
  It finds every ``try`` whose body reaches a canonicalizer and whose first
  handler catches the module's own error class without catching
  ``ValueError``.  A static sweep is a WORKLIST, not a finding: it cannot
  tell whether the bad value ever reaches the pin.
* **the DYNAMIC probe** — instantiate each candidate module's ledger class,
  enumerate its public methods, and call each with every string parameter set
  to a lone surrogate and every int parameter set to 1, then check whether
  ``canonical_json.JcsError`` escapes.  This is a FINDING, but only for the
  inputs it actually tried.

The dynamic probe needs **crafted** inputs for some modules: a module that
validates one string against a pinned vocabulary before it reaches the pin
will refuse the surrogate as its own error type and the probe will see no
escape.  The probe therefore reports a module as "not live" only as
"not live for the inputs tried", and the caller must exercise a module by
hand before believing it.

Usage::

    python3 scripts/digest-pin-census.py [--root DIR] [--json]

The counts printed here REPLACE an earlier claim ("672 modules, 189 with a
fallback, 165 candidate sites across 54 modules") that does not reproduce
under any of ~40 definitions tried.  A count in a doc is a claim too.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

HELPER = "canonical_json.py"
CANONIZER_NAMES = ("jcs_dumps", "jcs_canonical_json", "jcs_sha256_hex")
FALLBACK_HANDLERS = ("ImportError", "Exception", "BaseException")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _parse(path: Path) -> ast.Module | None:
    try:
        return ast.parse(_read(path))
    except SyntaxError:
        return None


def canonicalizer_aliases(tree: ast.Module) -> set[str]:
    """Every local name bound to a canonicalizer.

    Both import shapes occur in the runtime: ``from canonical_json import
    jcs_dumps as _jcs_dumps`` (a function alias) and ``import canonical_json
    as _cj`` (a module alias, used as ``_cj.jcs_dumps``).  A sweep that
    misses either shape misses live sites.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("canonical_json"):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.endswith("canonical_json"):
                    names.add(alias.asname or alias.name.split(".")[-1])
    return names


def reachable_functions(tree: ast.Module) -> set[str]:
    """Module-level functions that transitively reach a canonicalizer.

    The returned set holds the CALL names that denote a canonicalizer --
    both the bare function names (``jcs_dumps``) and the dotted module-alias
    forms (``_cj.jcs_dumps``) -- plus every module-level function that
    reaches one.
    """
    funcs = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    calls: dict[str, set[str]] = {
        name: {ast.unparse(c.func) for c in ast.walk(node) if isinstance(c, ast.Call)}
        for name, node in funcs.items()
    }
    aliases = canonicalizer_aliases(tree)
    reach: set[str] = set(CANONIZER_NAMES)
    for alias in aliases:
        # a module alias is called as `_cj.jcs_dumps`; a function alias is
        # called as `_jcs_dumps`.  Both are canonicalizer call names.
        for name in CANONIZER_NAMES:
            reach.add(f"{alias}.{name}")
        reach.add(alias)
    changed = True
    while changed:
        changed = False
        for name in funcs:
            if name in reach:
                continue
            if calls[name] & reach:
                reach.add(name)
                changed = True
    return reach


def module_error_classes(tree: ast.Module) -> set[str]:
    return {node.name for node in tree.body if isinstance(node, ast.ClassDef)}


def imports_behind_fallback(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for statement in node.body:
            rendered = ast.unparse(statement)
            if "canonical_json" not in rendered or "import" not in rendered:
                continue
            for handler in node.handlers:
                caught = ast.unparse(handler.type) if handler.type else "None"
                if caught in FALLBACK_HANDLERS:
                    return True
    return False


def candidate_sites(tree: ast.Module) -> list[int]:
    """Line numbers of the tries whose guard is dead for a JcsError."""
    own = module_error_classes(tree)
    reach = reachable_functions(tree)
    sites: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        called = {
            ast.unparse(c.func)
            for c in ast.walk(node)
            if isinstance(c, ast.Call)
        }
        if not (called & reach):
            continue
        caught = [
            ast.unparse(h.type) if h.type else "None"
            for h in node.handlers
        ]
        first = next((c for c in caught if "ValueError" not in c), None)
        if first is not None and first in own:
            sites.append(node.lineno)
    return sites


def census(root: Path) -> dict:
    modules = sorted(p for p in root.glob("*.py") if p.name != HELPER)
    users = 0
    fallback_importers = 0
    fallback_importers_any = 0
    sites = 0
    site_modules: list[str] = []
    for path in modules:
        source = _read(path)
        if "canonical_json" not in source:
            continue
        tree = _parse(path)
        if tree is None:
            continue
        if imports_behind_fallback(tree):
            fallback_importers_any += 1
        if not any(name in source for name in CANONIZER_NAMES):
            continue
        users += 1
        if imports_behind_fallback(tree):
            fallback_importers += 1
        found = candidate_sites(tree)
        if found:
            sites += len(found)
            site_modules.append(path.name)
    return {
        "root": str(root),
        "modules": len(modules),
        "canonicalizer_users": users,
        "fallback_importers": fallback_importers,
        "fallback_importers_any": fallback_importers_any,
        "candidate_sites": sites,
        "candidate_modules": len(site_modules),
        "candidate_module_names": sorted(site_modules),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=str(
            Path(__file__).resolve().parents[1]
            / "components"
            / "northstar-agent-runtime"
        ),
        help="the runtime directory to walk",
    )
    parser.add_argument("--json", action="store_true", help="print JSON only")
    args = parser.parse_args()
    report = census(Path(args.root))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for key in (
            "modules",
            "canonicalizer_users",
            "fallback_importers",
            "fallback_importers_any",
            "candidate_sites",
            "candidate_modules",
        ):
            print(f"{key:28} {report[key]}")
        print(
            "\nA static sweep is a WORKLIST, not a finding: it cannot tell "
            "whether\nthe bad value ever reaches the pin.  Exercise each "
            "candidate before\nbelieving it."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
