"""bs_13: Peak index in mountain array

Return the peak index of a mountain array (strictly increasing
then strictly decreasing).

Time complexity: O(log n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_13_VERSION = "bs-13.v1"


def peak_index_mountain(a):
    """Return the peak index of a mountain array."""
    lo, hi = 0, len(a) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] < a[mid + 1]:
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
    assert peak_index_mountain([0, 1, 0]) == 1
    assert peak_index_mountain([0, 2, 1, 0]) == 1
    assert peak_index_mountain([3, 5, 3, 2, 0]) == 1
    assert peak_index_mountain([0, 10, 5, 2]) == 1
    assert peak_index_mountain([1, 3, 2]) == 1
    assert stdlib_only()
    print("bs_13 OK")


if __name__ == "__main__":
    main()
