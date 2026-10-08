"""mat_21: Symmetric matrix check.

Check whether a square matrix equals its transpose.

Time complexity: O(n^2) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_21_VERSION = "mat-21.v1"


def is_symmetric(m):
    """Return True iff m equals its own transpose."""
    n = len(m)
    if any(len(row) != n for row in m):
        return False
    return all(m[i][j] == m[j][i] for i in range(n) for j in range(n))

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
    assert is_symmetric([[1,2],[2,1]]) is True
    assert is_symmetric([[1,2],[3,4]]) is False
    assert is_symmetric([[1,2,3],[2,4,5],[3,5,6]]) is True
    assert stdlib_only()
    print("mat_21 OK")


if __name__ == "__main__":
    main()
