"""Bubble sort: repeatedly swap adjacent out-of-order elements.

On each pass the largest unsorted element "bubbles" to the end of the
unsorted region. An early-exit stops the algorithm when a full pass makes
no swaps (already-sorted input).

Time complexity: O(n^2) worst/average, O(n) best (already sorted).
Space complexity: O(n) for the copied output list (O(1) auxiliary).
Stable: yes.
"""

import ast
import sys
from typing import List

ALGO_01_VERSION = "algo-01.v1"


def bubble_sort(arr: List[int]) -> List[int]:
    """Return a NEW list with the elements of ``arr`` sorted ascending."""
    a = list(arr)
    n = len(a)
    for end in range(n - 1, 0, -1):
        swapped = False
        for i in range(end):
            if a[i] > a[i + 1]:
                a[i], a[i + 1] = a[i + 1], a[i]
                swapped = True
        if not swapped:
            break
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
    assert bubble_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert bubble_sort([]) == []
    assert bubble_sort([7]) == [7]
    assert bubble_sort([1, 2, 3, 4]) == [1, 2, 3, 4]
    assert bubble_sort([4, 3, 2, 1]) == [1, 2, 3, 4]
    assert bubble_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]
    assert bubble_sort([-2, 0, -5, 3]) == [-5, -2, 0, 3]
    src = [3, 1, 2]
    assert bubble_sort(src) == [1, 2, 3] and src == [3, 1, 2]
    assert stdlib_only()
    print("algo-01 OK")


if __name__ == "__main__":
    main()
