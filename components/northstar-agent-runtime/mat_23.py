"""mat_23: Upper triangular check.

Check whether all elements below the main diagonal are zero.

Time complexity: O(m*n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_23_VERSION = "mat-23.v1"


def is_upper_tri(m):
    """Return True iff every element strictly below the diagonal is zero."""
    return all(m[i][j] == 0 for i in range(len(m))
               for j in range(len(m[0])) if i > j)

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
    assert is_upper_tri([[1,2],[0,3]]) is True
    assert is_upper_tri([[1,0],[2,3]]) is False
    assert is_upper_tri([[1,2,3],[0,4,5],[0,0,6]]) is True
    assert stdlib_only()
    print("mat_23 OK")


if __name__ == "__main__":
    main()
