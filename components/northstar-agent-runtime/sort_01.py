"""Bubble sort (basic): the textbook exchange sort.

Adjacent out-of-order pairs are swapped; the largest unsorted value sinks to the end on each pass.

What this IS: the classic O(n^2) bubble sort, correct on any comparable input.

What this IS NOT:
* Not adaptive -- it makes all n passes even on sorted input.
* Not stable-optimized; included as the baseline every other variant is measured against.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_01_VERSION = "sort-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-01.v1"


def sort(data: List[int]) -> List[int]:
    # Classic bubble sort: adjacent swaps, largest sinks each pass. O(n^2).
    a = list(data)
    n = len(a)
    for i in range(n):
        for j in range(n - i - 1):
            if a[j] > a[j + 1]:
                a[j], a[j + 1] = a[j + 1], a[j]
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
    print("bubble-basic OK")


if __name__ == "__main__":
    main()
