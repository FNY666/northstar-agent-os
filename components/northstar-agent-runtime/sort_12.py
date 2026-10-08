"""Merge sort (top-down): recursive divide and conquer.

Recursively splits the input in half and merges the sorted halves; the canonical stable O(n log n) sort.

What this IS: the textbook top-down merge sort.

What this IS NOT:
* Allocates O(n) extra lists; not the in-place bottom-up form.
* Recursion depth is O(log n).
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_12_VERSION = "sort-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-12.v1"


def _merge(left: List[int], right: List[int]) -> List[int]:
    out: List[int] = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            out.append(left[i])
            i += 1
        else:
            out.append(right[j])
            j += 1
    out.extend(left[i:])
    out.extend(right[j:])
    return out


def sort(data: List[int]) -> List[int]:
    # Top-down merge sort: recursively split, then merge.
    a = list(data)
    if len(a) <= 1:
        return a
    mid = len(a) // 2
    return _merge(sort(a[:mid]), sort(a[mid:]))

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
    print("merge-topdown OK")


if __name__ == "__main__":
    main()
