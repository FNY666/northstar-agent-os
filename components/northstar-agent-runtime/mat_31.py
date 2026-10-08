"""mat_31: 3x3 determinant.

Compute the determinant of a 3x3 matrix via the rule of Sarrus.

Time complexity: O(1) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_31_VERSION = "mat-31.v1"


def det3(m):
    """Return the determinant of a 3x3 matrix."""
    a, b, c = m[0]
    d, e, f = m[1]
    g, h, i = m[2]
    return a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)

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
    assert det3([[1,2,3],[4,5,6],[7,8,9]]) == 0
    assert det3([[2,1,3],[1,0,2],[3,2,1]]) == 3
    assert det3([[1,0,0],[0,1,0],[0,0,1]]) == 1
    assert stdlib_only()
    print("mat_31 OK")


if __name__ == "__main__":
    main()
