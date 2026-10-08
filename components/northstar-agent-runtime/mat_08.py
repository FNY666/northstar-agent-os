"""mat_08: Identity matrix check.

Check whether a matrix is an identity matrix.

Time complexity: O(n^2) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_08_VERSION = "mat-08.v1"


def is_identity(m):
    """Return True iff m is a square identity matrix."""
    n = len(m)
    if n == 0 or any(len(row) != n for row in m):
        return False
    return all(m[i][j] == (1 if i == j else 0)
               for i in range(n) for j in range(n))

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
    assert is_identity([[1,0],[0,1]]) is True
    assert is_identity([[1,0],[1,1]]) is False
    assert is_identity([[1,0,0],[0,1,0],[0,0,1]]) is True
    assert is_identity([[2,0],[0,1]]) is False
    assert stdlib_only()
    print("mat_08 OK")


if __name__ == "__main__":
    main()
