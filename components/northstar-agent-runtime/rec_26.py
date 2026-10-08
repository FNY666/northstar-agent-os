"""Nesting depth: 1 + max(child depths)

Atoms have depth 0; an empty list has depth 1.

What this IS: a real recursive nesting-depth measure.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_26_VERSION = "rec-nested-depth.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-nested-depth.v1"


class RecError(Exception):
    """Fail-closed."""


def depth(x) -> int:
    """Nesting depth of x."""
    if not isinstance(x, list):
        return 0
    if not x:
        return 1
    return 1 + max(depth(c) for c in x)

def test_depth_atom():
    assert depth(5) == 0


def test_depth_flat():
    assert depth([1, 2]) == 1


def test_depth_nested():
    assert depth([1, [2, [3]]]) == 3


def test_depth_empty():
    assert depth([]) == 1

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_depth_atom()
    test_depth_flat()
    test_depth_nested()
    test_depth_empty()
    assert stdlib_only()
    print("rec-nested-depth OK")


if __name__ == "__main__":
    main()
