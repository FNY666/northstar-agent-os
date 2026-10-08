"""Slow sort: multiply and surrender paradigm.

Recursively sorts both halves, ensures the maximum of the left half precedes the end, then recurses on all but the last element; correct and glacial.

What this IS: a real, intentionally pessimal sort: the opposite of quicksort's 'divide and conquer'.

What this IS NOT:
* Absurdly slow: far worse than bubble sort.
* Included as the family cautionary tale.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_50_VERSION = "sort-50.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-50.v1"


def _slow(a: List[int], i: int, j: int) -> None:
    if i >= j:
        return
    m = (i + j) // 2
    _slow(a, i, m)
    _slow(a, m + 1, j)
    if a[j] < a[m]:
        a[j], a[m] = a[m], a[j]
    _slow(a, i, j - 1)


def sort(data: List[int]) -> List[int]:
    # Slow sort ("multiply and surrender"): recursively sorts halves,
    # ensures the max of the left half precedes the end, then
    # recurses on all but the last. Correct and glacial.
    a = list(data)
    if len(a) > 1:
        _slow(a, 0, len(a) - 1)
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
    print("slow OK")


if __name__ == "__main__":
    main()
