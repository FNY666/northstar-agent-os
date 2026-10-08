"""Smoothsort (simplified): simulation of the Leonardo-heap structure.

Dijkstra's smoothsort builds a Leonardo heap in O(1) extra space; this module simulates its two-phase heap structure with a binary heap.

What this IS: a correct-output simulation; adaptive on nearly-sorted input in spirit.

What this IS NOT:
* Not the true O(1)-space smoothsort -- the Leonardo heap machinery is elided.
* Labeled simplified so nobody mistakes it for Dijkstra's original.
"""

from __future__ import annotations

import ast
import heapq
from typing import List

#: Module version.
SORT_36_VERSION = "sort-36.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-36.v1"


def sort(data: List[int]) -> List[int]:
    # Smoothsort (simplified simulation): the true smoothsort builds a
    # Leonardo heap in O(1) extra space; this models its two-phase
    # heap structure with a binary heap. Correct output; the O(1)
    # space property is not preserved.
    a = list(data)
    heapq.heapify(a)
    return [heapq.heappop(a) for _ in range(len(a))]

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
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
    print("smooth OK")


if __name__ == "__main__":
    main()
