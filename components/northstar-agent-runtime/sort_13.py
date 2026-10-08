"""Merge sort (bottom-up): iterative width-doubling merge.

Starts with runs of width 1 and iteratively merges adjacent runs, doubling the width each pass; no recursion.

What this IS: iterative merge sort with O(1) call-stack usage.

What this IS NOT:
* Still O(n) extra space for the merged runs.
* Slightly more index bookkeeping than the recursive form.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_13_VERSION = "sort-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-13.v1"


def sort(data: List[int]) -> List[int]:
    # Bottom-up merge sort: iteratively merge runs of doubling width.
    a = list(data)
    n = len(a)
    width = 1
    while width < n:
        for lo in range(0, n, 2 * width):
            mid = min(lo + width, n)
            hi = min(lo + 2 * width, n)
            left, right = a[lo:mid], a[mid:hi]
            i = j = 0
            out: List[int] = []
            while i < len(left) and j < len(right):
                if left[i] <= right[j]:
                    out.append(left[i])
                    i += 1
                else:
                    out.append(right[j])
                    j += 1
            out.extend(left[i:])
            out.extend(right[j:])
            a[lo:hi] = out
        width *= 2
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
    print("merge-bottomup OK")


if __name__ == "__main__":
    main()
