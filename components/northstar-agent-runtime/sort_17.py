"""Quicksort (Hoare): Hoare partition scheme.

Hoare partitioning with two inward-moving indices and a middle pivot; fewer swaps on average than Lomuto.

What this IS: the original 1961 quicksort partition scheme.

What this IS NOT:
* The returned index is not the pivot's final position.
* Still O(n^2) worst case without randomization.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_17_VERSION = "sort-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-17.v1"


def _partition(a: List[int], lo: int, hi: int) -> int:
    piv = a[(lo + hi) // 2]
    i, j = lo - 1, hi + 1
    while True:
        i += 1
        while a[i] < piv:
            i += 1
        j -= 1
        while a[j] > piv:
            j -= 1
        if i >= j:
            return j
        a[i], a[j] = a[j], a[i]


def _quick(a: List[int], lo: int, hi: int) -> None:
    if lo < hi:
        p = _partition(a, lo, hi)
        _quick(a, lo, p)
        _quick(a, p + 1, hi)


def sort(data: List[int]) -> List[int]:
    # Quicksort with Hoare's partition scheme (fewer swaps on average).
    a = list(data)
    _quick(a, 0, len(a) - 1)
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
    print("quick-hoare OK")


if __name__ == "__main__":
    main()
