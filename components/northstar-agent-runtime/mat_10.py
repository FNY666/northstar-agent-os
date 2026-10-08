"""mat_10: Row sums.

Compute the sum of each row of a matrix.

Time complexity: O(m*n) time
Space complexity: O(m) auxiliary"""

import ast
import sys
MAT_10_VERSION = "mat-10.v1"


def row_sums(m):
    """Return a list with the sum of each row."""
    return [sum(row) for row in m]

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
    assert row_sums([[1,2],[3,4]]) == [3,7]
    assert row_sums([[1,2,3],[4,5,6]]) == [6,15]
    assert row_sums([[]]) == [0]
    assert stdlib_only()
    print("mat_10 OK")


if __name__ == "__main__":
    main()
