"""Binary search: recursive halving

Halves the interval each call; O(log n) on sorted input.

What this IS: a real recursive binary search returning the index or -1.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_11_VERSION = "rec-bsearch.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-bsearch.v1"


class RecError(Exception):
    """Fail-closed."""


def bsearch(a, x, lo=0, hi=None) -> int:
    """Index of x in sorted a, or -1."""
    if hi is None:
        hi = len(a)
    if lo >= hi:
        return -1
    mid = (lo + hi) // 2
    if a[mid] == x:
        return mid
    if a[mid] < x:
        return bsearch(a, x, mid + 1, hi)
    return bsearch(a, x, lo, mid)

def test_bsearch_found():
    assert bsearch([1, 3, 5, 7, 9], 7) == 3


def test_bsearch_first():
    assert bsearch([1, 3, 5], 1) == 0


def test_bsearch_missing():
    assert bsearch([1, 3, 5], 4) == -1


def test_bsearch_empty():
    assert bsearch([], 1) == -1

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
    test_bsearch_found()
    test_bsearch_first()
    test_bsearch_missing()
    test_bsearch_empty()
    assert stdlib_only()
    print("rec-bsearch OK")


if __name__ == "__main__":
    main()
