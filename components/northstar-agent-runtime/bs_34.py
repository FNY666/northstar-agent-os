"""bs_34: Single element in sorted pairs array

Find the single non-duplicate element in a sorted array where
every other element appears exactly twice.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_34_VERSION = "bs-34.v1"


def single_non_duplicate(a):
    """Return the single element in a sorted pairs array."""
    lo, hi = 0, len(a) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if mid % 2 == 1:
            mid -= 1
        if a[mid] == a[mid + 1]:
            lo = mid + 2
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
    assert single_non_duplicate([1, 1, 2, 3, 3, 4, 4, 8, 8]) == 2
    assert single_non_duplicate([3, 3, 7, 7, 10, 11, 11]) == 10
    assert single_non_duplicate([1]) == 1
    assert single_non_duplicate([1, 1, 2]) == 2
    assert single_non_duplicate([0, 1, 1]) == 0
    assert stdlib_only()
    print("bs_34 OK")


if __name__ == "__main__":
    main()
