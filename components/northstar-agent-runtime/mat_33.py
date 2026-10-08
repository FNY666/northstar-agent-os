"""mat_33: 2x2 matrix inverse.

Compute the inverse of a non-singular 2x2 matrix.

Time complexity: O(1) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_33_VERSION = "mat-33.v1"


def _det2(m):
    return m[0][0] * m[1][1] - m[0][1] * m[1][0]


def _adj2(m):
    a, b = m[0]
    c, d = m[1]
    return [[d, -b], [-c, a]]


def _mm(a, b):
    n = len(b)
    return [[sum(a[i][k] * b[k][j] for k in range(n))
             for j in range(len(b[0]))] for i in range(len(a))]


def inverse2(m):
    """Return the inverse of a non-singular 2x2 matrix."""
    d = _det2(m)
    assert d != 0, "singular matrix"
    return [[x / d for x in row] for row in _adj2(m)]

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
    assert inverse2([[1,2],[3,4]]) == [[-2.0, 1.0], [1.5, -0.5]]
    assert inverse2([[2,0],[0,4]]) == [[0.5, 0.0], [0.0, 0.25]]
    assert (lambda p: all(abs(p[i][j] - (1 if i == j else 0)) < 1e-9 for i in range(2) for j in range(2)))(_mm([[1,2],[3,4]], inverse2([[1,2],[3,4]])))
    assert stdlib_only()
    print("mat_33 OK")


if __name__ == "__main__":
    main()
