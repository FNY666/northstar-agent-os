"""bs_07: Count occurrences

Number of occurrences of target in a sorted list, computed as
upper_bound - lower_bound.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_07_VERSION = "bs-07.v1"


def _lower_bound(a, target):
    lo, hi = 0, len(a)
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] < target:
            lo = mid + 1
        else:
            hi = mid
    return lo


def _upper_bound(a, target):
    lo, hi = 0, len(a)
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] <= target:
            lo = mid + 1
        else:
            hi = mid
    return lo


def count_occurrences(a, target):
    """Return how many times target appears in sorted list a."""
    return _upper_bound(a, target) - _lower_bound(a, target)

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
    assert count_occurrences([1, 2, 2, 3], 2) == 2
    assert count_occurrences([1, 2, 2, 3], 4) == 0
    assert count_occurrences([5, 5, 5], 5) == 3
    assert count_occurrences([], 1) == 0
    assert count_occurrences([1, 2, 3], 1) == 1
    assert stdlib_only()
    print("bs_07 OK")


if __name__ == "__main__":
    main()
