"""Shell sort: insertion sort generalized to shrinking gap sequences.

Elements ``gap`` apart are insertion-sorted; the gap starts at n//2 and
halves each round until it reaches 1 (a final plain insertion sort, which
is cheap because the array is nearly sorted by then).

Time complexity: O(n log n) average-ish, O(n^2) worst (depends on the gap
sequence; this halving sequence is simple but not optimal).
Space complexity: O(n) for the copied output list (O(1) auxiliary).
Stable: no.
"""

import ast
import sys
from typing import List

ALGO_10_VERSION = "algo-10.v1"


def shell_sort(arr: List[int]) -> List[int]:
    """Return a NEW list with the elements of ``arr`` sorted ascending."""
    a = list(arr)
    n = len(a)
    gap = n // 2
    while gap > 0:
        for i in range(gap, n):
            temp = a[i]
            j = i
            while j >= gap and a[j - gap] > temp:
                a[j] = a[j - gap]
                j -= gap
            a[j] = temp
        gap //= 2
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
    assert shell_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert shell_sort([]) == []
    assert shell_sort([7]) == [7]
    assert shell_sort([1, 2, 3, 4]) == [1, 2, 3, 4]
    assert shell_sort([4, 3, 2, 1]) == [1, 2, 3, 4]
    assert shell_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]
    assert shell_sort([12, -3, 0, 7, -3, 9]) == [-3, -3, 0, 7, 9, 12]
    src = [3, 1, 2]
    assert shell_sort(src) == [1, 2, 3] and src == [3, 1, 2]
    assert stdlib_only()
    print("algo-10 OK")


if __name__ == "__main__":
    main()
