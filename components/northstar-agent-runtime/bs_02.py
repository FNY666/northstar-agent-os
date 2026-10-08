"""bs_02: Recursive binary search

Recursive binary search on a sorted list. Returns the index of
target, or -1 when absent.

Time complexity: O(log n) time
Space complexity: O(log n) call stack"""

import ast
import sys
BS_02_VERSION = "bs-02.v1"


def binary_search_rec(a, target, lo=0, hi=None):
    """Return index of target in sorted list a, or -1 (recursive)."""
    if hi is None:
        hi = len(a) - 1
    if lo > hi:
        return -1
    mid = (lo + hi) // 2
    if a[mid] == target:
        return mid
    if a[mid] < target:
        return binary_search_rec(a, target, mid + 1, hi)
    return binary_search_rec(a, target, lo, mid - 1)

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
    assert binary_search_rec([1, 2, 3, 4, 5], 3) == 2
    assert binary_search_rec([1, 2, 3, 4, 5], 1) == 0
    assert binary_search_rec([1, 2, 3, 4, 5], 5) == 4
    assert binary_search_rec([1, 2, 3, 4, 5], 0) == -1
    assert binary_search_rec([], 1) == -1
    assert stdlib_only()
    print("bs_02 OK")


if __name__ == "__main__":
    main()
