"""Counting sort: frequency table with offset.

Counts occurrences of each key in [min, max], then emits keys in order; negatives handled by offsetting with the minimum.

What this IS: O(n + k) non-comparison sort for bounded integer ranges.

What this IS NOT:
* Memory is O(k) in the key range, not the input size.
* Only for integers (or mappable keys).
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_23_VERSION = "sort-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-23.v1"


def sort(data: List[int]) -> List[int]:
    # Counting sort: count occurrences via offset table, then emit.
    # O(n + k); handles negatives by offsetting with min(a).
    a = list(data)
    if not a:
        return a
    lo, hi = min(a), max(a)
    counts = [0] * (hi - lo + 1)
    for x in a:
        counts[x - lo] += 1
    out: List[int] = []
    for i, c in enumerate(counts):
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
    print("counting OK")


if __name__ == "__main__":
    main()
