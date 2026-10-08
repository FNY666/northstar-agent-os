"""bs_29: Exponential search

Find the range containing target by doubling, then binary
search inside it. Fast when the target is near the front.

Time complexity: O(log i) time where i is the target index
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_29_VERSION = "bs-29.v1"


def exponential_search(a, target):
    """Search target with exponential range finding + binary search."""
    n = len(a)
    if n == 0:
        return -1
    if a[0] == target:
        return 0
    i = 1
    while i < n and a[i] <= target:
        i *= 2
    lo, hi = i // 2, min(i, n - 1)
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == target:
            return mid
        if a[mid] < target:
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
    assert exponential_search([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 7) == 6
    assert exponential_search([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 1) == 0
    assert exponential_search([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 10) == 9
    assert exponential_search([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 11) == -1
    assert exponential_search([], 1) == -1
    assert stdlib_only()
    print("bs_29 OK")


if __name__ == "__main__":
    main()
