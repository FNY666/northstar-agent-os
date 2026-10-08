"""bs_04: Upper bound

First index i with a[i] > target. Returns len(a) when no
element is greater.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_04_VERSION = "bs-04.v1"


def upper_bound(a, target):
    """Return first index with a[i] > target."""
    lo, hi = 0, len(a)
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] <= target:
            lo = mid + 1
        else:
            hi = mid
    return lo

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
    assert upper_bound([1, 2, 2, 3], 2) == 3
    assert upper_bound([1, 2, 2, 3], 0) == 0
    assert upper_bound([1, 2, 2, 3], 3) == 4
    assert upper_bound([1, 2, 2, 3], 1) == 1
    assert upper_bound([], 5) == 0
    assert stdlib_only()
    print("bs_04 OK")


if __name__ == "__main__":
    main()
