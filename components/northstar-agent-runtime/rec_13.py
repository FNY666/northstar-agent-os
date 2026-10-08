"""Quick sort: partition around a pivot

Functional variant: elements < pivot, == pivot, > pivot, recursed. Average O(n log n).

What this IS: a real recursive quick sort.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_13_VERSION = "rec-quicksort.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-quicksort.v1"


class RecError(Exception):
    """Fail-closed."""


def quicksort(xs):
    """Sorted copy of xs."""
    if len(xs) <= 1:
        return list(xs)
    p = xs[0]
    lo = [x for x in xs[1:] if x < p]
    hi = [x for x in xs[1:] if x >= p]
    return quicksort(lo) + [p] + quicksort(hi)

def test_quicksort_empty():
    assert quicksort([]) == []


def test_quicksort_basic():
    assert quicksort([3, 1, 4, 1, 5, 9, 2, 6]) == [1, 1, 2, 3, 4, 5, 6, 9]


def test_quicksort_reverse():
    assert quicksort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]

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
    test_quicksort_empty()
    test_quicksort_basic()
    test_quicksort_reverse()
    assert stdlib_only()
    print("rec-quicksort OK")


if __name__ == "__main__":
    main()
