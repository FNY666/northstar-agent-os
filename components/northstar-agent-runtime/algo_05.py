"""Quick sort: partition around a pivot, conquer each side.

Implemented iteratively with an explicit stack plus median-of-three pivot
selection, so pathological inputs (already sorted, reverse sorted, all
equal) cannot cause recursion blowup: the stack depth stays O(log n)
because we always continue on the smaller partition and stack the larger.

Time complexity: O(n log n) average, O(n^2) worst (rare with median-of-three).
Space complexity: O(n) for the copy, O(log n) auxiliary stack.
Stable: no.
"""

import ast
import sys
from typing import List

ALGO_05_VERSION = "algo-05.v1"


def quick_sort(arr: List[int]) -> List[int]:
    """Return a NEW list with the elements of ``arr`` sorted ascending."""
    a = list(arr)
    n = len(a)
    if n < 2:
        return a
    stack = [(0, n - 1)]
    while stack:
        lo, hi = stack.pop()
        # Loop on the smaller partition, stack the larger: depth stays O(log n).
        while lo < hi:
            mid = (lo + hi) // 2
            # Median-of-three: order a[lo], a[mid], a[hi], pivot -> a[lo].
            if a[lo] > a[mid]:
                a[lo], a[mid] = a[mid], a[lo]
            if a[lo] > a[hi]:
                a[lo], a[hi] = a[hi], a[lo]
            if a[mid] > a[hi]:
                a[mid], a[hi] = a[hi], a[mid]
            a[mid], a[lo] = a[lo], a[mid]
            pivot = a[lo]
            # Hoare partition.
            i = lo - 1
            j = hi + 1
            while True:
                i += 1
                while a[i] < pivot:
                    i += 1
                j -= 1
                while a[j] > pivot:
                    j -= 1
                if i >= j:
                    break
                a[i], a[j] = a[j], a[i]
            if j - lo < hi - j:
                stack.append((j + 1, hi))
                hi = j
            else:
                stack.append((lo, j))
                lo = j + 1
    return a


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert quick_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert quick_sort([]) == []
    assert quick_sort([7]) == [7]
    # Pathological inputs: must not blow the recursion limit.
    assert quick_sort(list(range(5000))) == list(range(5000))
    assert quick_sort(list(range(5000, 0, -1))) == list(range(1, 5001))
    assert quick_sort([9] * 2000) == [9] * 2000
    assert quick_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]
    assert quick_sort([-5, 3, -5, 0, 2]) == [-5, -5, 0, 2, 3]
    src = [3, 1, 2]
    assert quick_sort(src) == [1, 2, 3] and src == [3, 1, 2]
    assert stdlib_only()
    print("algo-05 OK")


if __name__ == "__main__":
    main()
