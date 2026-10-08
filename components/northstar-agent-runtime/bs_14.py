"""bs_14: Search 2D matrix (flattened)

Search target in an m x n matrix whose rows are sorted and each
row starts after the previous row ends, via binary search on the
flattened index.

Time complexity: O(log(m*n)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_14_VERSION = "bs-14.v1"


def search_matrix(m, target):
    """Return True when target is in the row-major sorted matrix."""
    if not m or not m[0]:
        return False
    rows, cols = len(m), len(m[0])
    lo, hi = 0, rows * cols - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        v = m[mid // cols][mid % cols]
        if v == target:
            return True
        if v < target:
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
    assert search_matrix([[1, 3, 5, 7], [10, 11, 16, 20], [23, 30, 34, 60]], 3) is True
    assert search_matrix([[1, 3, 5, 7], [10, 11, 16, 20], [23, 30, 34, 60]], 13) is False
    assert search_matrix([], 1) is False
    assert search_matrix([[1]], 1) is True
    assert search_matrix([[1, 2], [3, 4]], 4) is True
    assert stdlib_only()
    print("bs_14 OK")


if __name__ == "__main__":
    main()
