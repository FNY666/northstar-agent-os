"""Nested max: max over leaves

Descends into sublists; fail-closed on empty input.

What this IS: a real recursive nested-list maximum, fail-closed on empty.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_50_VERSION = "rec-nested-max.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-nested-max.v1"


class RecError(Exception):
    """Fail-closed."""


def nested_max(xs):
    """Maximum leaf of a nested list. Fail-closed on empty."""
    best = None
    for x in xs:
        v = nested_max(x) if isinstance(x, list) else x
        if best is None or v > best:
            best = v
    if best is None:
        raise RecError("nested_max needs a non-empty list")
    return best

def test_nested_max_basic():
    assert nested_max([1, [5, [3]], 2]) == 5


def test_nested_max_flat():
    assert nested_max([4, 2, 9]) == 9


def test_nested_max_negative():
    assert nested_max([[-3], [-1]]) == -1


def test_nested_max_empty_raises():
    try:
        nested_max([])
    except RecError:
        return
    raise AssertionError("expected RecError")

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
    test_nested_max_basic()
    test_nested_max_flat()
    test_nested_max_negative()
    test_nested_max_empty_raises()
    assert stdlib_only()
    print("rec-nested-max OK")


if __name__ == "__main__":
    main()
