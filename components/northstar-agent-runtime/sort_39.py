"""Bitonic sort: bitonic network; pads to power of two.

Builds a bitonic sequence recursively and merge-sorts it with a compare-swap network; input is padded to a power of two with +inf.

What this IS: a data-independent sorting network: O(log^2 n) parallel depth.

What this IS NOT:
* Padding changes the working size, not the result.
* Sequentially O(n log^2 n) -- the win is parallelism.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_39_VERSION = "sort-39.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-39.v1"


def _bitonic_merge(a: list, lo: int, n: int, up: bool) -> None:
    if n > 1:
        m = n // 2
        for i in range(lo, lo + m):
            if (a[i] > a[i + m]) == up:
                a[i], a[i + m] = a[i + m], a[i]
        _bitonic_merge(a, lo, m, up)
        _bitonic_merge(a, lo + m, m, up)


def _bitonic_sort(a: list, lo: int, n: int, up: bool) -> None:
    if n > 1:
        m = n // 2
        _bitonic_sort(a, lo, m, True)
        _bitonic_sort(a, lo + m, m, False)
        _bitonic_merge(a, lo, n, up)


def sort(data: List[int]) -> List[int]:
    # Bitonic sort: sorting-network style; pads the input up to a
    # power of two with +inf, then sorts ascending.
    a = list(data)
    n = len(a)
    if n <= 1:
        return a
    size = 1
    while size < n:
        size *= 2
    a = a + [float("inf")] * (size - n)
    _bitonic_sort(a, 0, size, True)
    return a[:n]

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
    print("bitonic OK")


if __name__ == "__main__":
    main()
