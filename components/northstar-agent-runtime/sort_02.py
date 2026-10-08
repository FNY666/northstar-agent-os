"""Bubble sort (optimized): early exit plus last-swap bound.

Adds the two standard bubble sort optimizations: stop when a pass makes no swaps, and shrink the next pass to the last swap position.

What this IS: an adaptive bubble sort that is O(n) on already-sorted input.

What this IS NOT:
* Still O(n^2) worst case.
* The optimizations do not change the comparison structure, only prune it.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_02_VERSION = "sort-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-02.v1"


def sort(data: List[int]) -> List[int]:
    # Optimized bubble: stops early when a pass makes no swaps, and
    # shrinks the bound to the last swap position.
    a = list(data)
    n = len(a)
    while n > 1:
        last = 0
        for j in range(n - 1):
            if a[j] > a[j + 1]:
                a[j], a[j + 1] = a[j + 1], a[j]
                last = j + 1
        if last == 0:
            break
        n = last
    return a

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
    print("bubble-opt OK")


if __name__ == "__main__":
    main()
