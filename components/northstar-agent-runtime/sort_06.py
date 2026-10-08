"""Insertion sort (binary): bisect finds the insertion point.

Same insertion structure, but binary search (via bisect) locates the insertion point in O(log n) comparisons; the shift stays O(n).

What this IS: insertion sort with O(n log n) comparisons.

What this IS NOT:
* Moves are still O(n^2); only comparisons improve.
* Uses the stdlib bisect module for the search.
"""

from __future__ import annotations

import ast
import bisect
from typing import List

#: Module version.
SORT_06_VERSION = "sort-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-06.v1"


def sort(data: List[int]) -> List[int]:
    # Binary insertion sort: bisect finds the insertion point in
    # O(log n) comparisons; the shift is still O(n).
    out: List[int] = []
    for x in data:
        bisect.insort(out, x)
    return out

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "bisect", "pathlib", "typing"}
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
    print("insertion-binary OK")


if __name__ == "__main__":
    main()
