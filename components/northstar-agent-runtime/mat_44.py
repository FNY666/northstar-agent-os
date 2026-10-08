"""mat_44: Matrix power.

Raise a square matrix to a non-negative integer power.

Time complexity: O(k*n^3) time
Space complexity: O(n^2) auxiliary"""

import ast
import sys
MAT_44_VERSION = "mat-44.v1"


def mat_pow(m, k):
    """Return m raised to the k-th power (k >= 0)."""
    n = len(m)
    result = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    for _ in range(k):
        result = [[sum(result[i][t] * m[t][j] for t in range(n))
                   for j in range(n)] for i in range(n)]
    return result

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
    assert mat_pow([[1,1],[1,0]], 5) == [[8,5],[5,3]]
    assert mat_pow([[2,0],[0,2]], 3) == [[8,0],[0,8]]
    assert mat_pow([[1,2],[3,4]], 0) == [[1,0],[0,1]]
    assert mat_pow([[1,2],[3,4]], 1) == [[1,2],[3,4]]
    assert stdlib_only()
    print("mat_44 OK")


if __name__ == "__main__":
    main()
