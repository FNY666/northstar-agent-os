"""bs_11: Search rotated array with duplicates

Check whether target exists in a rotated sorted array that may
contain duplicates. Returns a boolean.

Time complexity: O(log n) average, O(n) worst case
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_11_VERSION = "bs-11.v1"


def search_rotated_dups(a, target):
    """Return True when target is in rotated sorted array (duplicates ok)."""
    lo, hi = 0, len(a) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == target:
            return True
        if a[lo] == a[mid] == a[hi]:
            lo += 1
            hi -= 1
        elif a[lo] <= a[mid]:
            if a[lo] <= target < a[mid]:
                hi = mid - 1
            else:
                lo = mid + 1
        else:
            if a[mid] < target <= a[hi]:
                lo = mid + 1
            else:
                hi = mid - 1
    return False

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
    assert search_rotated_dups([2, 5, 6, 0, 0, 1, 2], 0) is True
    assert search_rotated_dups([2, 5, 6, 0, 0, 1, 2], 3) is False
    assert search_rotated_dups([1, 0, 1, 1, 1], 0) is True
    assert search_rotated_dups([1], 2) is False
    assert search_rotated_dups([1, 1, 1], 1) is True
    assert stdlib_only()
    print("bs_11 OK")


if __name__ == "__main__":
    main()
