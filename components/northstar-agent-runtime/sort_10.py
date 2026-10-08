"""Selection sort (basic): repeated minimum selection.

Each pass scans the unsorted suffix for its minimum and swaps it into place; exactly n swaps.

What this IS: the minimal-write comparison sort: O(n) swaps.

What this IS NOT:
* Always O(n^2) comparisons, even on sorted input.
* Not stable in this in-place form.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_10_VERSION = "sort-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-10.v1"


def sort(data: List[int]) -> List[int]:
    # Basic selection sort: each pass selects the minimum of the
    # unsorted suffix and swaps it into place.
    a = list(data)
    n = len(a)
    for i in range(n):
        mn = i
        for j in range(i + 1, n):
            if a[j] < a[mn]:
                mn = j
        a[i], a[mn] = a[mn], a[i]
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
    print("selection-basic OK")


if __name__ == "__main__":
    main()
