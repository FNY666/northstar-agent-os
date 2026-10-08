"""Bucket sort: range buckets with insertion sort each.

Scatters values into n buckets spanning [min, max], insertion-sorts each bucket, then concatenates.

What this IS: O(n) average for uniformly distributed input.

What this IS NOT:
* Degrades to O(n^2) if all values land in one bucket.
* Needs min/max up front for the range mapping.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_26_VERSION = "sort-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-26.v1"


def sort(data: List[int]) -> List[int]:
    # Bucket sort: scatter into n range buckets, insertion-sort each,
    # concatenate. Assumes roughly uniform distribution.
    a = list(data)
    n = len(a)
    if n <= 1:
        return a
    lo, hi = min(a), max(a)
    if lo == hi:
        return a
    buckets: List[List[int]] = [[] for _ in range(n)]
    span = hi - lo
    for x in a:
        idx = min(n - 1, (x - lo) * n // (span + 1))
        buckets[idx].append(x)
    out: List[int] = []
    for b in buckets:
        for i in range(1, len(b)):
            key = b[i]
            j = i - 1
            while j >= 0 and b[j] > key:
                b[j + 1] = b[j]
                j -= 1
            b[j + 1] = key
        out.extend(b)
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
    print("bucket OK")


if __name__ == "__main__":
    main()
