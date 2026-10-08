"""Pancake sort: prefix reversals only.

The only allowed operation is flipping a prefix; repeatedly bring the maximum of the unsorted prefix to the front, then flip it to the end.

What this IS: sorting by prefix reversals; at most 2n - 3 flips.

What this IS NOT:
* Not the optimal-flip variant (which is NP-hard to compute).
* This greedy version uses at most 2 flips per element.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_33_VERSION = "sort-33.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-33.v1"


def sort(data: List[int]) -> List[int]:
    # Pancake sort: only operation is reversing a prefix. Bring the
    # max of the unsorted prefix to the front, then flip it to the end.
    a = list(data)
    n = len(a)
    for size in range(n, 1, -1):
        mx = 0
        for i in range(1, size):
            if a[i] > a[mx]:
                mx = i
        if mx != size - 1:
            a[: mx + 1] = a[: mx + 1][::-1]
            a[:size] = a[:size][::-1]
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
    print("pancake OK")


if __name__ == "__main__":
    main()
