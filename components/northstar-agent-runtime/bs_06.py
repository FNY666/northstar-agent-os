"""bs_06: Last occurrence

Index of the last occurrence of target in a sorted list with
duplicates, or -1 when absent.

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_06_VERSION = "bs-06.v1"


def _upper_bound(a, target):
    lo, hi = 0, len(a)
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] <= target:
            lo = mid + 1
        else:
            hi = mid
    return lo


def last_occurrence(a, target):
    """Return last index of target, or -1."""
    i = _upper_bound(a, target) - 1
    if i >= 0 and a[i] == target:
        return i
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
    assert last_occurrence([1, 2, 2, 3], 2) == 2
    assert last_occurrence([1, 2, 2, 3], 4) == -1
    assert last_occurrence([1, 2, 2, 3], 3) == 3
    assert last_occurrence([], 1) == -1
    assert last_occurrence([2, 2, 2], 2) == 2
    assert stdlib_only()
    print("bs_06 OK")


if __name__ == "__main__":
    main()
