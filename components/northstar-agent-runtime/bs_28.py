"""bs_28: Binary search on descending array

Classic binary search adapted to a list sorted in descending
order.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_28_VERSION = "bs-28.v1"


def binary_search_desc(a, target):
    """Return index of target in a descending sorted list, or -1."""
    lo, hi = 0, len(a) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == target:
            return mid
        if a[mid] > target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1

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
    assert binary_search_desc([5, 4, 3, 2, 1], 3) == 2
    assert binary_search_desc([5, 4, 3, 2, 1], 5) == 0
    assert binary_search_desc([5, 4, 3, 2, 1], 1) == 4
    assert binary_search_desc([5, 4, 3, 2, 1], 6) == -1
    assert binary_search_desc([], 1) == -1
    assert stdlib_only()
    print("bs_28 OK")


if __name__ == "__main__":
    main()
