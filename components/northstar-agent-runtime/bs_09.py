"""bs_09: Minimum in rotated sorted array

Find the minimum value of a rotated sorted array without
duplicates.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_09_VERSION = "bs-09.v1"


def find_min_rotated(a):
    """Return the minimum of a rotated sorted array (no duplicates)."""
    lo, hi = 0, len(a) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] > a[hi]:
            lo = mid + 1
        else:
            hi = mid
    return a[lo]

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
    assert find_min_rotated([3, 4, 5, 1, 2]) == 1
    assert find_min_rotated([1, 2, 3]) == 1
    assert find_min_rotated([2, 1]) == 1
    assert find_min_rotated([1]) == 1
    assert find_min_rotated([5, 1, 2, 3, 4]) == 1
    assert stdlib_only()
    print("bs_09 OK")


if __name__ == "__main__":
    main()
