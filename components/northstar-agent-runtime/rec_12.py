"""Merge sort: divide, sort, merge

Splits in half, sorts each half, merges in linear time. O(n log n).

What this IS: a real recursive merge sort.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_12_VERSION = "rec-mergesort.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-mergesort.v1"


class RecError(Exception):
    """Fail-closed."""


def mergesort(xs):
    """Sorted copy of xs."""
    if len(xs) <= 1:
        return list(xs)
    mid = len(xs) // 2
    left = mergesort(xs[:mid])
    right = mergesort(xs[mid:])
    out, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            out.append(left[i]); i += 1
        else:
            out.append(right[j]); j += 1
    out.extend(left[i:]); out.extend(right[j:])
    return out

def test_mergesort_empty():
    assert mergesort([]) == []


def test_mergesort_basic():
    assert mergesort([3, 1, 4, 1, 5, 9, 2, 6]) == [1, 1, 2, 3, 4, 5, 6, 9]


def test_mergesort_sorted():
    assert mergesort([1, 2, 3]) == [1, 2, 3]


def test_mergesort_single():
    assert mergesort([7]) == [7]

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_mergesort_empty()
    test_mergesort_basic()
    test_mergesort_sorted()
    test_mergesort_single()
    assert stdlib_only()
    print("rec-mergesort OK")


if __name__ == "__main__":
    main()
