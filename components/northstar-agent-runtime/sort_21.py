"""Heap sort (binary heap): max-heap extract loop.

Builds a binary max-heap in place, then repeatedly swaps the root (maximum) to the end of the unsorted region.

What this IS: the classic in-place O(n log n) heap sort.

What this IS NOT:
* Not stable.
* Poor cache locality compared to quicksort/merge sort.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_21_VERSION = "sort-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-21.v1"


def _sift(a: List[int], root: int, end: int) -> None:
    while True:
        child = 2 * root + 1
        if child > end:
            return
        if child + 1 <= end and a[child] < a[child + 1]:
            child += 1
        if a[root] < a[child]:
            a[root], a[child] = a[child], a[root]
            root = child
        else:
            return


def sort(data: List[int]) -> List[int]:
    # Heap sort: build a max-heap, then repeatedly extract the max.
    a = list(data)
    n = len(a)
    for r in range(n // 2 - 1, -1, -1):
        _sift(a, r, n - 1)
    for end in range(n - 1, 0, -1):
        a[0], a[end] = a[end], a[0]
        _sift(a, 0, end - 1)
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
    print("heap-binary OK")


if __name__ == "__main__":
    main()
