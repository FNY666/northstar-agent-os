"""mat_04: Scalar multiplication.

Multiply every element of a matrix by a scalar.

Time complexity: O(m*n) time
Space complexity: O(m*n) auxiliary"""

import ast
import sys
MAT_04_VERSION = "mat-04.v1"


def scalar_mul(k, m):
    """Return k * m with every element scaled by k."""
    return [[k * x for x in row] for row in m]

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
    assert scalar_mul(2, [[1,2],[3,4]]) == [[2,4],[6,8]]
    assert scalar_mul(0, [[1,2],[3,4]]) == [[0,0],[0,0]]
    assert scalar_mul(-1, [[1,-2],[3,-4]]) == [[-1,2],[-3,4]]
    assert stdlib_only()
    print("mat_04 OK")


if __name__ == "__main__":
    main()
