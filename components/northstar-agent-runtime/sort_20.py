"""Introsort: quicksort with heapsort fallback.

Starts as quicksort; when recursion depth exceeds 2*log2(n) it switches that partition to heapsort, and uses insertion sort for tiny partitions.

What this IS: the O(n log n) worst-case hybrid behind C++ std::sort.

What this IS NOT:
* Not stable.
* The depth guard adds a log computation up front.
"""

from __future__ import annotations

import ast
import math
from typing import List

#: Module version.
SORT_20_VERSION = "sort-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-20.v1"


def _insertion(a: List[int], lo: int, hi: int) -> None:
    for i in range(lo + 1, hi + 1):
        key = a[i]
        j = i - 1
        while j >= lo and a[j] > key:
            a[j + 1] = a[j]
            j -= 1
        a[j + 1] = key


def _sift(a: List[int], root: int, lo: int, hi: int) -> None:
    while True:
        child = 2 * root + 1
        if lo + child > hi:
            return
        if lo + child + 1 <= hi and a[lo + child] < a[lo + child + 1]:
            child += 1
        if a[lo + root] < a[lo + child]:
            a[lo + root], a[lo + child] = a[lo + child], a[lo + root]
            root = child
        else:
            return


def _heapsort(a: List[int], lo: int, hi: int) -> None:
    n = hi - lo + 1
    for r in range(n // 2 - 1, -1, -1):
        _sift(a, r, lo, hi)
    for end in range(n - 1, 0, -1):
        a[lo], a[lo + end] = a[lo + end], a[lo]
        _sift(a, 0, lo, lo + end - 1)


def _lomuto(a: List[int], lo: int, hi: int) -> int:
    piv = a[hi]
    i = lo
    for j in range(lo, hi):
        if a[j] <= piv:
            a[i], a[j] = a[j], a[i]
            i += 1
    a[i], a[hi] = a[hi], a[i]
    return i


def _intro(a: List[int], lo: int, hi: int, depth: int) -> None:
    n = hi - lo + 1
    if n <= 16:
        _insertion(a, lo, hi)
        return
    if depth == 0:
        _heapsort(a, lo, hi)
        return
    p = _lomuto(a, lo, hi)
    _intro(a, lo, p - 1, depth - 1)
    _intro(a, p + 1, hi, depth - 1)


def sort(data: List[int]) -> List[int]:
    # Introsort: quicksort, but switches to heapsort when the
    # recursion depth exceeds 2*log2(n), and insertion sort for
    # tiny partitions. O(n log n) worst case.
    a = list(data)
    n = len(a)
    if n > 1:
        _intro(a, 0, n - 1, 2 * math.floor(math.log2(n)))
    return a

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
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
    print("introsort OK")


if __name__ == "__main__":
    main()
