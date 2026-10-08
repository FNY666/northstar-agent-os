"""Patience sort: pile formation plus k-way merge.

Deals each card onto the leftmost pile whose top is >= it (bisect on pile tops), then k-way merges the piles after reversing each to ascending order.

What this IS: O(n log n); the pile count also reveals the longest decreasing subsequence.

What this IS NOT:
* Needs the merge phase to produce sorted output (piles alone do not).
* Uses heapq.merge from the stdlib.
"""

from __future__ import annotations

import ast
import bisect
import heapq
from typing import List

#: Module version.
SORT_35_VERSION = "sort-35.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-35.v1"


def sort(data: List[int]) -> List[int]:
    # Patience sort: deal cards into piles (bisect on pile tops), then
    # k-way merge the piles. O(n log n). Piles are dealt in
    # non-increasing order, so each is reversed before merging.
    a = list(data)
    if not a:
        return a
    piles: List[List[int]] = []
    tops: List[int] = []
    for x in a:
        i = bisect.bisect_left(tops, x)
        if i == len(piles):
            piles.append([x])
            tops.append(x)
        else:
            piles[i].append(x)
            tops[i] = x
    return list(heapq.merge(*[p[::-1] for p in piles]))

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "bisect", "heapq", "pathlib", "typing"}
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
    print("patience OK")


if __name__ == "__main__":
    main()
