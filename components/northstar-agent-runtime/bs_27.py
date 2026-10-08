"""bs_27: Search nearly sorted array

Search target in an array where every element is at most one
position away from its sorted place.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_27_VERSION = "bs-27.v1"


def search_nearly_sorted(a, target):
    """Search target in a nearly sorted array; -1 when absent."""
    lo, hi = 0, len(a) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == target:
            return mid
        if mid - 1 >= lo and a[mid - 1] == target:
            return mid - 1
        if mid + 1 <= hi and a[mid + 1] == target:
            return mid + 1
        if a[mid] < target:
            lo = mid + 2
        else:
            hi = mid - 2
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
    assert search_nearly_sorted([10, 3, 40, 20, 80], 20) == 3
    assert search_nearly_sorted([10, 3, 40, 20, 80], 3) == 1
    assert search_nearly_sorted([10, 3, 40, 20, 80], 100) == -1
    assert search_nearly_sorted([10, 3, 40, 20, 80], 80) == 4
    assert search_nearly_sorted([3], 3) == 0
    assert search_nearly_sorted([10, 3, 40, 20, 80], 10) == 0
    assert stdlib_only()
    print("bs_27 OK")


if __name__ == "__main__":
    main()
