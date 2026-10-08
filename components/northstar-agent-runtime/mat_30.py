"""mat_30: 2x2 determinant.

Compute the determinant of a 2x2 matrix.

Time complexity: O(1) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_30_VERSION = "mat-30.v1"


def det2(m):
    """Return the determinant of a 2x2 matrix."""
    return m[0][0] * m[1][1] - m[0][1] * m[1][0]

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
    assert det2([[1,2],[3,4]]) == -2
    assert det2([[2,0],[0,3]]) == 6
    assert det2([[1,1],[1,1]]) == 0
    assert stdlib_only()
    print("mat_30 OK")


if __name__ == "__main__":
    main()
