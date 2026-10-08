"""Comb sort: bubble sort with a shrinking gap.

Compares elements gap apart instead of adjacent; the gap starts at n and shrinks by a factor of 1.3 each pass, finishing with a gap-1 bubble pass.

What this IS: a genuine improvement over bubble sort that kills turtles early via long-range swaps.

What this IS NOT:
* Not O(n log n) in the worst case.
* The 1.3 shrink factor is empirical, not proven optimal.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_04_VERSION = "sort-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-04.v1"


def sort(data: List[int]) -> List[int]:
    # Comb sort: like bubble sort but compares elements gap apart,
    # shrinking the gap by 1.3 each pass; finishes with gap 1.
    a = list(data)
    n = len(a)
    gap = n
    swapped = True
    while gap > 1 or swapped:
        gap = max(1, int(gap / 1.3))
        swapped = False
        for j in range(n - gap):
            if a[j] > a[j + gap]:
                a[j], a[j + gap] = a[j + gap], a[j]
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
    print("comb OK")


if __name__ == "__main__":
    main()
