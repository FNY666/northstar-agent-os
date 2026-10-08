"""mat_48: Boolean matrix multiplication.

Multiply matrices with AND-OR (boolean) semantics.

Time complexity: O(m*n*p) time
Space complexity: O(m*p) auxiliary"""

import ast
import sys
MAT_48_VERSION = "mat-48.v1"


def bool_matmul(a, b):
    """Return the boolean product of a and b using AND-OR semantics."""
    p = len(b[0])
    return [[1 if any(a[i][k] and b[k][j] for k in range(len(b))) else 0
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
    assert bool_matmul([[1,0],[0,1]], [[0,1],[1,0]]) == [[0,1],[1,0]]
    assert bool_matmul([[1,1],[0,1]], [[1,0],[1,1]]) == [[1,1],[1,1]]
    assert bool_matmul([[0,0],[0,0]], [[1,1],[1,1]]) == [[0,0],[0,0]]
    assert stdlib_only()
    print("mat_48 OK")


if __name__ == "__main__":
    main()
