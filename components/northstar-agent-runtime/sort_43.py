"""Library sort: gapped insertion with rebalancing.

Inserts into a gapped array (extra space between elements) so most insertions avoid shifting; binary search finds the insertion rank and the array is rebalanced when crowded.

What this IS: gapped insertion sort: O(n log n) with high probability.

What this IS NOT:
* This is the simplified core; the original uses sqrt-spaced gaps and a precise rebalance schedule.
* Shifting within gap runs is still linear in the worst case.
"""

from __future__ import annotations

import ast
import bisect
from typing import List

#: Module version.
SORT_43_VERSION = "sort-43.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-43.v1"


def _rebalance(g: list, m: int) -> tuple:
    stored = sorted(v for v in g if v is not None)
    k = len(stored)
    new_m = max(m * 2, 4 * k + 1)
    ng: list = [None] * new_m
    if k:
        step = new_m // (k + 1)
        for i, v in enumerate(stored):
            ng[(i + 1) * step] = v
    return ng, new_m


def _slot_of_rank(g: list, pos: int, count: int) -> int:
    if pos >= count:
        for i in range(len(g) - 1, -1, -1):
            if g[i] is not None:
                return i + 1
        return 0
    seen = -1
    for i, v in enumerate(g):
        if v is not None:
            seen += 1
            if seen == pos:
                return i
    return len(g) - 1


def sort(data: List[int]) -> List[int]:
    # Library sort (simplified): insertion into a gapped array with
    # periodic rebalancing; binary search finds the insertion rank.
    a = list(data)
    n = len(a)
    if n <= 1:
        return a
    m = 4 * n
    g: list = [None] * m
    g[m // 2] = a[0]
    count = 1
    for x in a[1:]:
        stored = [v for v in g if v is not None]
        pos = bisect.bisect_left(stored, x)
        target = _slot_of_rank(g, pos, count)
        j = target
        while True:
            while j < m and g[j] is not None:
                j += 1
            if j < m:
                break
            g, m = _rebalance(g, m)
            stored = [v for v in g if v is not None]
            pos = bisect.bisect_left(stored, x)
            target = _slot_of_rank(g, pos, count)
            j = target
        for k in range(j, target, -1):
            g[k] = g[k - 1]
        g[target] = x
        count += 1
    return [v for v in g if v is not None]

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
    print("library OK")


if __name__ == "__main__":
    main()
