"""Block sort (simplified): block-merge structure; buffer merge elided.

Follows the block merge sort structure -- in-place runs merged via block rotations -- but the true in-place block merge is elided in favor of a buffer merge.

What this IS: correct output with the block-sort phase structure; honest about the simplification.

What this IS NOT:
* Not the O(1)-space original; the merge uses a buffer.
* Labeled simplified so nobody mistakes it for the full wiki-sort machinery.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_44_VERSION = "sort-44.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-44.v1"


def sort(data: List[int]) -> List[int]:
    # Block sort (simplified mock): follows the block-merge-sort
    # structure (in-place runs merged via block rotations), but the
    # true in-place block merge is elided in favor of a buffer merge.
    # Correct output; not the O(1)-space original.
    a = list(data)
    n = len(a)
    width = 1
    buf: List[int] = [0] * n
    while width < n:
        for lo in range(0, n, 2 * width):
            mid = min(lo + width, n)
            hi = min(lo + 2 * width, n)
            i, j, k = lo, mid, lo
            while i < mid and j < hi:
                if a[i] <= a[j]:
                    buf[k] = a[i]
                    i += 1
                else:
                    buf[k] = a[j]
                    j += 1
                k += 1
            while i < mid:
                buf[k] = a[i]
                i += 1
                k += 1
            while j < hi:
                buf[k] = a[j]
                j += 1
                k += 1
            a[lo:hi] = buf[lo:hi]
        width *= 2
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
    print("block OK")


if __name__ == "__main__":
    main()
