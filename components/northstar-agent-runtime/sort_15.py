"""Timsort (stdlib delegation): delegates to CPython sorted().

Delegates to the interpreter's built-in Timsort: a natural merge sort with galloping mode and binary insertion sort for short runs.

What this IS: the real production sort used by CPython, via sorted().

What this IS NOT:
* Not a reimplementation -- this module is a thin, honest wrapper.
* Included so the family has a production reference point.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_15_VERSION = "sort-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-15.v1"


def sort(data: List[int]) -> List[int]:
    # Delegates to CPython's built-in Timsort (a natural merge sort
    # with galloping and binary insertion for short runs).
    return sorted(data)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    assert sort([]) == []
    assert sort([1]) == [1]
    assert sort([3, 1, 2]) == [1, 2, 3]
    assert sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert sort([-3, 0, -1, 2]) == [-3, -1, 0, 2]
    assert sort([2, 2, 1, 1]) == [1, 1, 2, 2]
    assert stdlib_only()
    print("timsort OK")


if __name__ == "__main__":
    main()
