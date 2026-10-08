"""mat_26: Scalar matrix check.

Check whether a matrix is a scalar multiple of the identity.

Time complexity: O(n^2) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_26_VERSION = "mat-26.v1"


def is_scalar(m):
    """Return True iff m == k * I for some scalar k."""
    n = len(m)
    if n == 0 or any(len(r) != n for r in m):
        return False
    v = m[0][0]
    return all(m[i][j] == (v if i == j else 0)
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
    assert is_scalar([[2,0],[0,2]]) is True
    assert is_scalar([[1,0],[0,2]]) is False
    assert is_scalar([[3,0,0],[0,3,0],[0,0,3]]) is True
    assert stdlib_only()
    print("mat_26 OK")


if __name__ == "__main__":
    main()
