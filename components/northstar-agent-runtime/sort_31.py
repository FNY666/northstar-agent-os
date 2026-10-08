"""Odd-even sort (brick): phased parallel compare-swap.

Alternates odd-indexed and even-indexed adjacent compare-swap phases until a full cycle makes no swaps; each phase is data-parallel.

What this IS: a parallel-friendly O(n^2) sort used in hardware sorters.

What this IS NOT:
* Sequentially no better than bubble sort.
* Its value is the parallel structure, not modeled here.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_31_VERSION = "sort-31.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-31.v1"


def sort(data: List[int]) -> List[int]:
    # Odd-even (brick) sort: alternate odd-indexed and even-indexed
    # compare-swap phases until a full pass makes no swaps.
    a = list(data)
    n = len(a)
    swapped = True
    while swapped:
        swapped = False
        for j in range(1, n - 1, 2):
            if a[j] > a[j + 1]:
                a[j], a[j + 1] = a[j + 1], a[j]
                swapped = True
        for j in range(0, n - 1, 2):
            if a[j] > a[j + 1]:
                a[j], a[j + 1] = a[j + 1], a[j]
                swapped = True
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
    print("odd-even OK")


if __name__ == "__main__":
    main()
