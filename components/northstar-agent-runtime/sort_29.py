"""Stooge sort: recursive triple overlap; real but slow.

If the ends are out of order, swap them; then recursively sort the first two-thirds, the last two-thirds, and the first two-thirds again.

What this IS: a real, correct, famously inefficient sort: O(n^2.7).

What this IS NOT:
* One of the slowest correct sorts known.
* Recursion depth is logarithmic, but call count explodes.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_29_VERSION = "sort-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-29.v1"


def _stooge(a: List[int], lo: int, hi: int) -> None:
    if a[lo] > a[hi]:
        a[lo], a[hi] = a[hi], a[lo]
    if hi - lo + 1 > 2:
        t = (hi - lo + 1) // 3
        _stooge(a, lo, hi - t)
        _stooge(a, lo + t, hi)
        _stooge(a, lo, hi - t)


def sort(data: List[int]) -> List[int]:
    # Stooge sort: recursively sort overlapping two-thirds. Real but
    # famously slow: O(n^2.7).
    a = list(data)
    if a:
        _stooge(a, 0, len(a) - 1)
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
    print("stooge OK")


if __name__ == "__main__":
    main()
