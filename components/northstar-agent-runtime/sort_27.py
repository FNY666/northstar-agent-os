"""Pigeonhole sort: one hole per key value.

Like counting sort but conceptually one 'hole' per distinct key: place each element in its hole, then read holes in order.

What this IS: O(n + k) for dense integer key ranges.

What this IS NOT:
* Same range-memory cost as counting sort.
* Only sensible when the key range is small.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_27_VERSION = "sort-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-27.v1"


def sort(data: List[int]) -> List[int]:
    # Pigeonhole sort: one hole per distinct key value in [min, max].
    a = list(data)
    if not a:
        return a
    lo, hi = min(a), max(a)
    holes = [0] * (hi - lo + 1)
    for x in a:
        holes[x - lo] += 1
    out: List[int] = []
    for i, c in enumerate(holes):
        out.extend([i + lo] * c)
    return out

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
    print("pigeonhole OK")


if __name__ == "__main__":
    main()
