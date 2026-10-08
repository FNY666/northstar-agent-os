"""Selection sort (double-ended): min and max selected per pass.

Each pass selects both the minimum and the maximum of the unsorted region, placing both at the ends; halves the number of passes.

What this IS: selection sort with half the passes of the basic version.

What this IS NOT:
* Still O(n^2) comparisons.
* Needs care when min and max indices collide after the first swap.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_11_VERSION = "sort-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-11.v1"


def sort(data: List[int]) -> List[int]:
    # Double-ended selection: each pass selects both the minimum and
    # the maximum of the unsorted region.
    a = list(data)
    lo, hi = 0, len(a) - 1
    while lo < hi:
        mn, mx = lo, lo
        for j in range(lo + 1, hi + 1):
            if a[j] < a[mn]:
                mn = j
            if a[j] > a[mx]:
                mx = j
        a[lo], a[mn] = a[mn], a[lo]
        if mx == lo:
            mx = mn
        a[hi], a[mx] = a[mx], a[hi]
        lo += 1
        hi -= 1
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
    print("selection-double OK")


if __name__ == "__main__":
    main()
