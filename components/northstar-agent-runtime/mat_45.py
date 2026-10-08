"""mat_45: Add scalar to diagonal.

Add a scalar to each diagonal element of a square matrix.

Time complexity: O(n^2) time
Space complexity: O(n^2) auxiliary"""

import ast
import sys
MAT_45_VERSION = "mat-45.v1"


def add_to_diagonal(m, k):
    """Return a copy of m with k added to each diagonal element."""
    return [[x + (k if i == j else 0) for j, x in enumerate(row)]
            for i, row in enumerate(m)]

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
    assert add_to_diagonal([[1,2],[3,4]], 10) == [[11,2],[3,14]]
    assert add_to_diagonal([[1,2],[3,4]], 0) == [[1,2],[3,4]]
    assert add_to_diagonal([[5]], -5) == [[0]]
    assert stdlib_only()
    print("mat_45 OK")


if __name__ == "__main__":
    main()
