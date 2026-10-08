"""mat_35: Row max and min.

Compute the maximum and minimum of each row.

Time complexity: O(m*n) time
Space complexity: O(m) auxiliary"""

import ast
import sys
MAT_35_VERSION = "mat-35.v1"


def row_max(m):
    """Return the maximum of each row."""
    return [max(row) for row in m]


def row_min(m):
    """Return the minimum of each row."""
    return [min(row) for row in m]

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
    assert row_max([[1,5],[9,2]]) == [5,9]
    assert row_min([[1,5],[9,2]]) == [1,2]
    assert row_max([[-1,-2],[-3,-4]]) == [-1,-3]
    assert row_min([[-1,-2],[-3,-4]]) == [-2,-4]
    assert stdlib_only()
    print("mat_35 OK")


if __name__ == "__main__":
    main()
