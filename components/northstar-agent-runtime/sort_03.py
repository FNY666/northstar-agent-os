"""Cocktail shaker sort: bidirectional bubble sort.

Bubble passes alternate direction: left-to-right pushes large values up, right-to-left pulls small values down.

What this IS: a bidirectional bubble sort that fixes the 'turtle' problem of one-directional bubbling.

What this IS NOT:
* Still O(n^2) worst case.
* Only a constant-factor improvement over basic bubble sort.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_03_VERSION = "sort-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-03.v1"


def sort(data: List[int]) -> List[int]:
    # Cocktail shaker: bubble passes alternate left-to-right and
    # right-to-left, moving small values down as well as large values up.
    a = list(data)
    lo, hi = 0, len(a) - 1
    while lo < hi:
        for j in range(lo, hi):
            if a[j] > a[j + 1]:
                a[j], a[j + 1] = a[j + 1], a[j]
        hi -= 1
        for j in range(hi, lo, -1):
            if a[j] < a[j - 1]:
                a[j], a[j - 1] = a[j - 1], a[j]
        lo += 1
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
    print("cocktail OK")


if __name__ == "__main__":
    main()
