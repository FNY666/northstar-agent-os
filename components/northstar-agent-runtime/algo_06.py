"""Heap sort: build a max-heap, then repeatedly extract the maximum.

Phase 1 heapifies the array in place (sift-down from the last parent).
Phase 2 swaps the heap root to the end of the unsorted region and
restores the heap, growing the sorted suffix from the right.

Time complexity: O(n log n) always.
Space complexity: O(n) for the copied output list (O(1) auxiliary).
Stable: no.
"""

import ast
import sys
from typing import List

ALGO_06_VERSION = "algo-06.v1"


def heap_sort(arr: List[int]) -> List[int]:
    """Return a NEW list with the elements of ``arr`` sorted ascending."""
    a = list(arr)
    n = len(a)

    def sift_down(root: int, end: int) -> None:
        while True:
            child = 2 * root + 1
            if child > end:
                return
            if child + 1 <= end and a[child] < a[child + 1]:
                child += 1
            if a[root] < a[child]:
                a[root], a[child] = a[child], a[root]
                root = child
            else:
                return

    for start in range(n // 2 - 1, -1, -1):
        sift_down(start, n - 1)
    for end in range(n - 1, 0, -1):
        a[0], a[end] = a[end], a[0]
        sift_down(0, end - 1)
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
    assert heap_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert heap_sort([]) == []
    assert heap_sort([7]) == [7]
    assert heap_sort([1, 2, 3, 4]) == [1, 2, 3, 4]
    assert heap_sort([4, 3, 2, 1]) == [1, 2, 3, 4]
    assert heap_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]
    assert heap_sort([0, -9, 4, -9, 2]) == [-9, -9, 0, 2, 4]
    src = [3, 1, 2]
    assert heap_sort(src) == [1, 2, 3] and src == [3, 1, 2]
    assert stdlib_only()
    print("algo-06 OK")


if __name__ == "__main__":
    main()
