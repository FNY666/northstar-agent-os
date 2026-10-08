"""Flash sort: classification permutation plus insertion finish.

Classifies elements into m buckets by value range, permutes them into roughly-sorted position in place, then finishes with insertion sort.

What this IS: a real distribution sort: O(n) average on uniform data.

What this IS NOT:
* Needs the insertion finish -- classification alone only approximates order.
* Worst case degrades when classification is skewed.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_45_VERSION = "sort-45.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-45.v1"


def sort(data: List[int]) -> List[int]:
    # Flash sort: classify into buckets, permute into near-order,
    # finish with insertion sort.
    a = list(data)
    n = len(a)
    if n <= 1:
        return a
    lo, hi = min(a), max(a)
    if lo == hi:
        return a
    m = max(2, int(0.45 * n))

    def cls(x: int) -> int:
        return (m - 1) * (x - lo) // (hi - lo)

    L = [0] * m
    for x in a:
        L[cls(x)] += 1
    for k in range(1, m):
        L[k] += L[k - 1]
    moves = 0
    i = 0
    k = m - 1
    while moves < n - 1:
        while i >= L[k]:
            i += 1
            k = cls(a[i])
        z = a[i]
        while i != L[k]:
            k = cls(z)
            L[k] -= 1
            a[L[k]], z = z, a[L[k]]
            moves += 1
    for i in range(1, n):
        key = a[i]
        j = i - 1
        while j >= 0 and a[j] > key:
            a[j + 1] = a[j]
            j -= 1
        a[j + 1] = key
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
    print("flash OK")


if __name__ == "__main__":
    main()
