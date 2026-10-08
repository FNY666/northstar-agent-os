"""bs_03: Lower bound

First index i with a[i] >= target (insertion point). Returns
len(a) when every element is smaller.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_03_VERSION = "bs-03.v1"


def lower_bound(a, target):
    """Return first index with a[i] >= target."""
    lo, hi = 0, len(a)
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] < target:
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
    assert lower_bound([1, 2, 2, 3], 2) == 1
    assert lower_bound([1, 2, 2, 3], 0) == 0
    assert lower_bound([1, 2, 2, 3], 4) == 4
    assert lower_bound([1, 2, 2, 3], 3) == 3
    assert lower_bound([], 5) == 0
    assert stdlib_only()
    print("bs_03 OK")


if __name__ == "__main__":
    main()
