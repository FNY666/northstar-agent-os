"""Insertion sort: build the sorted prefix one element at a time.

Each new element is inserted into its correct position within the already
sorted prefix by shifting larger elements one slot to the right.

Time complexity: O(n^2) worst/average, O(n) best (already sorted).
Space complexity: O(n) for the copied output list (O(1) auxiliary).
Stable: yes.
"""

import ast
import sys
from typing import List

ALGO_02_VERSION = "algo-02.v1"


def insertion_sort(arr: List[int]) -> List[int]:
    """Return a NEW list with the elements of ``arr`` sorted ascending."""
    a = list(arr)
    for i in range(1, len(a)):
        key = a[i]
        j = i - 1
        while j >= 0 and a[j] > key:
            a[j + 1] = a[j]
            j -= 1
        a[j + 1] = key
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
    assert insertion_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert insertion_sort([]) == []
    assert insertion_sort([7]) == [7]
    assert insertion_sort([1, 2, 3, 4]) == [1, 2, 3, 4]
    assert insertion_sort([4, 3, 2, 1]) == [1, 2, 3, 4]
    assert insertion_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]
    assert insertion_sort([0, -1, -1, 5]) == [-1, -1, 0, 5]
    src = [3, 1, 2]
    assert insertion_sort(src) == [1, 2, 3] and src == [3, 1, 2]
    assert stdlib_only()
    print("algo-02 OK")


if __name__ == "__main__":
    main()
