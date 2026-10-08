"""mat_03: Matrix multiplication.

Multiply an m x n matrix by an n x p matrix (dot-product semantics).

Time complexity: O(m*n*p) time
Space complexity: O(m*p) auxiliary"""

import ast
import sys
MAT_03_VERSION = "mat-03.v1"


def mat_mul(a, b):
    """Return the product of an m x n matrix a and an n x p matrix b."""
    n = len(b)
    p = len(b[0])
    return [[sum(a[i][k] * b[k][j] for k in range(n))
             for j in range(p)] for i in range(len(a))]

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
    assert mat_mul([[1,2],[3,4]], [[5,6],[7,8]]) == [[19,22],[43,50]]
    assert mat_mul([[1,2,3]], [[4],[5],[6]]) == [[32]]
    assert mat_mul([[1,0],[0,1]], [[7,8],[9,10]]) == [[7,8],[9,10]]
    assert stdlib_only()
    print("mat_03 OK")


if __name__ == "__main__":
    main()
