"""Merge sort: divide and conquer with linear merging.

Implemented iteratively (bottom-up): runs of size 1, 2, 4, ... are merged
pairwise until the whole list is one sorted run. No recursion is used, so
there is no recursion-depth concern on large inputs.

Time complexity: O(n log n) always.
Space complexity: O(n) for the copy plus O(n) merge scratch.
Stable: yes.
"""

import ast
import sys
from typing import List

ALGO_04_VERSION = "algo-04.v1"


def merge_sort(arr: List[int]) -> List[int]:
    """Return a NEW list with the elements of ``arr`` sorted ascending."""
    a = list(arr)
    n = len(a)
    width = 1
    while width < n:
        for lo in range(0, n, 2 * width):
            mid = min(lo + width, n)
            hi = min(lo + 2 * width, n)
            left = a[lo:mid]
            right = a[mid:hi]
            i = j = 0
            k = lo
            while i < len(left) and j < len(right):
                if left[i] <= right[j]:
                    a[k] = left[i]
                    i += 1
                else:
                    a[k] = right[j]
                    j += 1
                k += 1
            while i < len(left):
                a[k] = left[i]
                i += 1
                k += 1
            while j < len(right):
                a[k] = right[j]
                j += 1
                k += 1
        width *= 2
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
    assert merge_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert merge_sort([]) == []
    assert merge_sort([7]) == [7]
    assert merge_sort([1, 2, 3, 4]) == [1, 2, 3, 4]
    assert merge_sort([4, 3, 2, 1]) == [1, 2, 3, 4]
    assert merge_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]
    assert merge_sort([9, -4, 0, 7, -4, 2]) == [-4, -4, 0, 2, 7, 9]
    src = [3, 1, 2]
    assert merge_sort(src) == [1, 2, 3] and src == [3, 1, 2]
    assert stdlib_only()
    print("algo-04 OK")


if __name__ == "__main__":
    main()
