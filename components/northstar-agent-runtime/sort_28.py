"""Gnome sort: garden-gnome walk and swap.

Walks forward through the list; on finding a disorder, swaps and steps back, like a garden gnome sorting flower pots.

What this IS: insertion sort's eccentric cousin; O(n^2) but simple and adaptive.

What this IS NOT:
* No better than insertion sort in any regime.
* Included for the family portrait, not for speed.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_28_VERSION = "sort-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-28.v1"


def sort(data: List[int]) -> List[int]:
    # Gnome sort: walk forward; step back and swap on disorder.
    a = list(data)
    i = 0
    n = len(a)
    while i < n:
        if i == 0 or a[i] >= a[i - 1]:
            i += 1
        else:
            a[i], a[i - 1] = a[i - 1], a[i]
            i -= 1
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
    print("gnome OK")


if __name__ == "__main__":
    main()
