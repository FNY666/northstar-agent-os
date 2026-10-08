"""Quicksort (Lomuto): Lomuto partition scheme.

Lomuto partitioning with the last element as pivot; recurses on the smaller side first to bound stack depth.

What this IS: quicksort in its most teachable partition form.

What this IS NOT:
* Degrades on many duplicates (use the 3-way variant instead).
* Worst case O(n^2) on adversarial input.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_16_VERSION = "sort-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-16.v1"


def _partition(a: List[int], lo: int, hi: int) -> int:
    piv = a[hi]
    i = lo
    for j in range(lo, hi):
        if a[j] <= piv:
            a[i], a[j] = a[j], a[i]
            i += 1
    a[i], a[hi] = a[hi], a[i]
    return i


def _quick(a: List[int], lo: int, hi: int) -> None:
    while lo < hi:
        p = _partition(a, lo, hi)
        if p - lo < hi - p:
            _quick(a, lo, p - 1)
            lo = p + 1
        else:
            _quick(a, p + 1, hi)
            hi = p - 1


def sort(data: List[int]) -> List[int]:
    # Quicksort with Lomuto's partition scheme; recurses on the
    # smaller side first to bound stack depth.
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
    print("quick-lomuto OK")


if __name__ == "__main__":
    main()
