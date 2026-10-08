"""bs_10: Minimum in rotated array with duplicates

Find the minimum value of a rotated sorted array that may
contain duplicates.

Time complexity: O(log n) average, O(n) worst case
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_10_VERSION = "bs-10.v1"


def find_min_rotated_dups(a):
    """Return the minimum of a rotated sorted array (duplicates allowed)."""
    lo, hi = 0, len(a) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] > a[hi]:
            lo = mid + 1
        elif a[mid] < a[hi]:
            hi = mid
        else:
            hi -= 1
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
    assert find_min_rotated_dups([2, 2, 2, 0, 1]) == 0
    assert find_min_rotated_dups([1, 3, 5]) == 1
    assert find_min_rotated_dups([3, 3, 1, 3]) == 1
    assert find_min_rotated_dups([1, 1, 1]) == 1
    assert find_min_rotated_dups([10, 1, 10, 10, 10]) == 1
    assert stdlib_only()
    print("bs_10 OK")


if __name__ == "__main__":
    main()
