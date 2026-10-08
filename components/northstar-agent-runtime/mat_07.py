"""mat_07: Diagonal extraction.

Extract the main diagonal of a square matrix as a list.

Time complexity: O(n) time
Space complexity: O(n) auxiliary"""

import ast
import sys
MAT_07_VERSION = "mat-07.v1"


def diagonal(m):
    """Return the main diagonal of square matrix m as a list."""
    return [m[i][i] for i in range(len(m))]

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
    assert diagonal([[1,2],[3,4]]) == [1,4]
    assert diagonal([[1,2,3],[4,5,6],[7,8,9]]) == [1,5,9]
    assert diagonal([[7]]) == [7]
    assert stdlib_only()
    print("mat_07 OK")


if __name__ == "__main__":
    main()
