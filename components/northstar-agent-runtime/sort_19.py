"""Quicksort (dual-pivot): Yaroslavskiy two-pivot partition.

Uses two pivots per partition step, splitting the range into three parts; the scheme that ships in Java's Arrays.sort for primitives.

What this IS: a real dual-pivot quicksort following Yaroslavskiy's algorithm.

What this IS NOT:
* More intricate index bookkeeping than single-pivot forms.
* Gains show mainly on large inputs, not tiny ones.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_19_VERSION = "sort-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-19.v1"


def _dual_pivot(a: List[int], left: int, right: int) -> None:
    if right <= left:
        return
    if a[left] > a[right]:
        a[left], a[right] = a[right], a[left]
    p, q = a[left], a[right]
    l, g, k = left + 1, right - 1, left + 1
    while k <= g:
        if a[k] < p:
            a[k], a[l] = a[l], a[k]
            l += 1
        elif a[k] >= q:
            while a[g] > q and k < g:
                g -= 1
            a[k], a[g] = a[g], a[k]
            g -= 1
            if a[k] < p:
                a[k], a[l] = a[l], a[k]
                l += 1
        k += 1
    l -= 1
    g += 1
    a[left], a[l] = a[l], a[left]
    a[right], a[g] = a[g], a[right]
    _dual_pivot(a, left, l - 1)
    _dual_pivot(a, l + 1, g - 1)
    _dual_pivot(a, g + 1, right)


def sort(data: List[int]) -> List[int]:
    # Dual-pivot quicksort (Yaroslavskiy): two pivots split the range
    # into three parts per partition step.
    a = list(data)
    _dual_pivot(a, 0, len(a) - 1)
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
    print("quick-dual OK")


if __name__ == "__main__":
    main()
