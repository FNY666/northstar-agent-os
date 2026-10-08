"""mat_36: Column max and min.

Compute the maximum and minimum of each column.

Time complexity: O(m*n) time
Space complexity: O(n) auxiliary"""

import ast
import sys
MAT_36_VERSION = "mat-36.v1"


def col_max(m):
    """Return the maximum of each column."""
    return [max(row[j] for row in m) for j in range(len(m[0]))]


def col_min(m):
    """Return the minimum of each column."""
    return [min(row[j] for row in m) for j in range(len(m[0]))]

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
    assert col_max([[1,5],[9,2]]) == [9,5]
    assert col_min([[1,5],[9,2]]) == [1,2]
    assert col_max([[1,2,3]]) == [1,2,3]
    assert stdlib_only()
    print("mat_36 OK")


if __name__ == "__main__":
    main()
