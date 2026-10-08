"""Quicksort (3-way): Dutch national flag partitioning.

Dijkstra's 3-way partition splits each range into < pivot, == pivot, and > pivot; duplicates are skipped in one pass.

What this IS: the duplicate-friendly quicksort; O(n) on all-equal input.

What this IS NOT:
* Slightly more bookkeeping per partition than Lomuto.
* Still needs the introsort guard for adversarial input.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_18_VERSION = "sort-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-18.v1"


def _quick(a: List[int], lo: int, hi: int) -> None:
    if lo >= hi:
        return
    piv = a[lo]
    lt, i, gt = lo, lo + 1, hi
    while i <= gt:
        if a[i] < piv:
            a[lt], a[i] = a[i], a[lt]
            lt += 1
            i += 1
        elif a[i] > piv:
            a[i], a[gt] = a[gt], a[i]
            gt -= 1
        else:
            i += 1
    _quick(a, lo, lt - 1)
    _quick(a, gt + 1, hi)


def sort(data: List[int]) -> List[int]:
    # 3-way quicksort (Dijkstra's Dutch national flag): partitions
    # into < pivot, == pivot, > pivot; ideal with many duplicates.
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
    print("quick-3way OK")


if __name__ == "__main__":
    main()
