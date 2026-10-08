"""Selection sort: repeatedly pick the minimum of the unsorted region.

On pass ``i`` the smallest element of ``a[i:]`` is found and swapped into
position ``i``, growing the sorted prefix from the left.

Time complexity: O(n^2) always (the full scan runs even on sorted input).
Space complexity: O(n) for the copied output list (O(1) auxiliary).
Stable: no (the swap can reorder equal elements).
"""

import ast
import sys
from typing import List

ALGO_03_VERSION = "algo-03.v1"


def selection_sort(arr: List[int]) -> List[int]:
    """Return a NEW list with the elements of ``arr`` sorted ascending."""
    a = list(arr)
    n = len(a)
    for i in range(n - 1):
        m = i
        for j in range(i + 1, n):
            if a[j] < a[m]:
                m = j
        if m != i:
            a[i], a[m] = a[m], a[i]
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
    assert selection_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert selection_sort([]) == []
    assert selection_sort([7]) == [7]
    assert selection_sort([1, 2, 3, 4]) == [1, 2, 3, 4]
    assert selection_sort([4, 3, 2, 1]) == [1, 2, 3, 4]
    assert selection_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]
    assert selection_sort([-3, -1, -2]) == [-3, -2, -1]
    src = [3, 1, 2]
    assert selection_sort(src) == [1, 2, 3] and src == [3, 1, 2]
    assert stdlib_only()
    print("algo-03 OK")


if __name__ == "__main__":
    main()
