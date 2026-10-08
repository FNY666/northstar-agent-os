"""bs_15: Search 2D matrix II (staircase)

Search target in a matrix with rows and columns each sorted
ascending, walking the staircase from the top-right corner.

Time complexity: O(m + n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_15_VERSION = "bs-15.v1"


def search_matrix2(m, target):
    """Return True when target is in a row/column sorted matrix."""
    if not m or not m[0]:
        return False
    r, c = len(m) - 1, 0
    while r >= 0 and c < len(m[0]):
        v = m[r][c]
        if v == target:
            return True
        if v > target:
            r -= 1
        else:
            c += 1
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
    m = [[1, 4, 7, 11, 15], [2, 5, 8, 12, 19], [3, 6, 9, 16, 22], [10, 13, 14, 17, 24], [18, 21, 23, 26, 30]]
    assert search_matrix2(m, 5) is True
    assert search_matrix2(m, 20) is False
    assert search_matrix2([], 1) is False
    assert search_matrix2([[1]], 2) is False
    assert search_matrix2(m, 30) is True
    assert stdlib_only()
    print("bs_15 OK")


if __name__ == "__main__":
    main()
