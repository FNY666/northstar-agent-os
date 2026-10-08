"""mat_32: 2x2 adjugate.

Compute the adjugate (classical adjoint) of a 2x2 matrix.

Time complexity: O(1) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_32_VERSION = "mat-32.v1"


def adjugate2(m):
    """Return the adjugate of a 2x2 matrix [[a,b],[c,d]] -> [[d,-b],[-c,a]]."""
    a, b = m[0]
    c, d = m[1]
    return [[d, -b], [-c, a]]


def _mm(a, b):
    n = len(b)
    return [[sum(a[i][k] * b[k][j] for k in range(n))
             for j in range(len(b[0]))] for i in range(len(a))]

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
    assert adjugate2([[1,2],[3,4]]) == [[4,-2],[-3,1]]
    assert adjugate2([[2,0],[0,2]]) == [[2,0],[0,2]]
    assert _mm(adjugate2([[1,2],[3,4]]), [[1,2],[3,4]]) == [[-2,0],[0,-2]]
    assert stdlib_only()
    print("mat_32 OK")


if __name__ == "__main__":
    main()
