"""Heap sort (ternary heap): 3-ary heap variant.

Same heap sort structure on a ternary heap: each node has three children, so the tree is shallower but each sift compares more children.

What this IS: heap sort generalized to d=3; fewer levels, more comparisons per level.

What this IS NOT:
* Rarely faster than binary heap sort in practice.
* Still not stable.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_22_VERSION = "sort-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-22.v1"


def _sift3(a: List[int], root: int, end: int) -> None:
    while True:
        first = 3 * root + 1
        if first > end:
            return
        big = first
        for c in (first + 1, first + 2):
            if c <= end and a[c] > a[big]:
                big = c
        if a[root] < a[big]:
            a[root], a[big] = a[big], a[root]
            root = big
        else:
            return


def sort(data: List[int]) -> List[int]:
    # Heap sort on a ternary (3-ary) heap: shallower tree, more
    # comparisons per sift.
    a = list(data)
    n = len(a)
    r = n // 3
    while r >= 0:
        _sift3(a, r, n - 1)
        r -= 1
    for end in range(n - 1, 0, -1):
        a[0], a[end] = a[end], a[0]
        _sift3(a, 0, end - 1)
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
    print("heap-ternary OK")


if __name__ == "__main__":
    main()
