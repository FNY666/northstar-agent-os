"""Insertion sort (basic): linear-scan insertion.

Grows the sorted prefix one element at a time, scanning backwards linearly to find each insertion point.

What this IS: the standard O(n^2) insertion sort; fast on nearly-sorted input.

What this IS NOT:
* Not the binary variant -- comparisons are linear here.
* Included as the baseline for the insertion family.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_05_VERSION = "sort-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-05.v1"


def sort(data: List[int]) -> List[int]:
    # Basic insertion sort: grow the sorted prefix one element at a time.
    a = list(data)
    for i in range(1, len(a)):
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
    print("insertion-basic OK")


if __name__ == "__main__":
    main()
