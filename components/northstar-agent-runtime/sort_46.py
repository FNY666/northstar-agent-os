"""Circle sort (corrected): overlapping recursive compare-swap.

Each pass compare-swaps symmetric pairs around each segment's center, recursing into halves that overlap by one element so every adjacent pair is compared each pass. The published non-overlapping form can stall on inputs like [.., 14, 11, ..]; the overlap fixes it. Passes repeat until one makes no swaps.

What this IS: a corrected circle sort: provably terminates because every swap moves a larger value right, strictly increasing the position-weighted sum.

What this IS NOT:
* Not the published 2014 formulation -- that one is not always correct, and this module says so.
* The overlap adds redundant comparisons; the win is correctness, not speed.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_46_VERSION = "sort-46.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-46.v1"


def _circle(a: List[int], lo: int, hi: int) -> bool:
    if lo >= hi:
        return False
    swapped = False
    l, r = lo, hi
    while l < r:
        if a[l] > a[r]:
            a[l], a[r] = a[r], a[l]
            swapped = True
        l += 1
        r -= 1
    if hi - lo >= 2:
        # Overlapping halves: (lo, mid) and (mid, hi) share mid, so
        # every adjacent pair is compared in each full pass.
        mid = (lo + hi) // 2
        if _circle(a, lo, mid):
            swapped = True
        if _circle(a, mid, hi):
            swapped = True
    return swapped


def sort(data: List[int]) -> List[int]:
    # Circle sort (corrected): recursively compare-swap symmetric
    # pairs; halves overlap by one element so every adjacent pair is
    # compared per pass. Repeat passes until one makes no swaps.
    # Termination: each swap moves a larger value to a higher index,
    # strictly increasing sum(i * a[i]), which is bounded above.
    a = list(data)
    if len(a) > 1:
        while _circle(a, 0, len(a) - 1):
            pass
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
    print("circle OK")


if __name__ == "__main__":
    main()
