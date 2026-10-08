"""mat_11: Column sums.

Compute the sum of each column of a matrix.

Time complexity: O(m*n) time
Space complexity: O(n) auxiliary"""

import ast
import sys
MAT_11_VERSION = "mat-11.v1"


def col_sums(m):
    """Return a list with the sum of each column."""
    return [sum(row[j] for row in m) for j in range(len(m[0]))]

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
    assert col_sums([[1,2],[3,4]]) == [4,6]
    assert col_sums([[1,2,3],[4,5,6]]) == [5,7,9]
    assert col_sums([[5]]) == [5]
    assert stdlib_only()
    print("mat_11 OK")


if __name__ == "__main__":
    main()
