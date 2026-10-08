"""Nested-list flatten: recurse into sublists

Keeps element order; only list instances are descended into.

What this IS: a real recursive flattener for nested lists.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_25_VERSION = "rec-flatten.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-flatten.v1"


class RecError(Exception):
    """Fail-closed."""


def flatten(xs):
    """Flatten one nested list."""
    out = []
    for x in xs:
        if isinstance(x, list):
            out.extend(flatten(x))
        else:
            out.append(x)
    return out

def test_flatten_nested():
    assert flatten([1, [2, [3, 4]], 5]) == [1, 2, 3, 4, 5]


def test_flatten_flat():
    assert flatten([1, 2, 3]) == [1, 2, 3]


def test_flatten_empty():
    assert flatten([]) == []


def test_flatten_deep():
    assert flatten([[[[1]]]]) == [1]

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
    test_flatten_nested()
    test_flatten_flat()
    test_flatten_empty()
    test_flatten_deep()
    assert stdlib_only()
    print("rec-flatten OK")


if __name__ == "__main__":
    main()
