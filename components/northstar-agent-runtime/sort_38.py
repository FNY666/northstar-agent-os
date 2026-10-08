"""Tournament sort: winner-tree repeated minimum extraction.

Builds a winner tree (tournament bracket) over the input padded to a power of two, then repeatedly extracts the winner and replays its matches.

What this IS: heap sort's tournament-bracket cousin; O(n log n).

What this IS NOT:
* Needs power-of-two padding (here with +inf).
* More memory traffic than a binary heap.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_38_VERSION = "sort-38.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-38.v1"


def sort(data: List[int]) -> List[int]:
    # Tournament sort: build a winner tree over the input, then
    # repeatedly extract the winner and replay its matches.
    a = list(data)
    n = len(a)
    if n <= 1:
        return a
    size = 1
    while size < n:
        size *= 2
    inf = float("inf")
    tree = [inf] * (2 * size)
    for i, x in enumerate(a):
        tree[size + i] = x
    for i in range(size - 1, 0, -1):
        tree[i] = tree[2 * i] if tree[2 * i] <= tree[2 * i + 1] else tree[2 * i + 1]
    out: List[int] = []
    for _ in range(n):
        w = tree[1]
        out.append(w)
        i = 1
        while i < size:
            i = 2 * i if tree[2 * i] == w else 2 * i + 1
        tree[i] = inf
        i //= 2
        while i >= 1:
            tree[i] = tree[2 * i] if tree[2 * i] <= tree[2 * i + 1] else tree[2 * i + 1]
            i //= 2
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
    print("tournament OK")


if __name__ == "__main__":
    main()
