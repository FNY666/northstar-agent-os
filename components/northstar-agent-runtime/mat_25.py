"""mat_25: Diagonal matrix check.

Check whether all off-diagonal elements are zero.

Time complexity: O(m*n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_25_VERSION = "mat-25.v1"


def is_diagonal(m):
    """Return True iff m is a square matrix with zeros off the diagonal."""
    n = len(m)
    if any(len(row) != n for row in m):
        return False
    return all(m[i][j] == 0 for i in range(n) for j in range(n) if i != j)

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
    assert is_diagonal([[1,0],[0,2]]) is True
    assert is_diagonal([[1,2],[0,2]]) is False
    assert is_diagonal([[5]]) is True
    assert stdlib_only()
    print("mat_25 OK")


if __name__ == "__main__":
    main()
