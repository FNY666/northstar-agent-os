"""mat_34: Solve 2x2 linear system.

Solve a @ x = b for a 2x2 matrix via Cramer's rule.

Time complexity: O(1) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_34_VERSION = "mat-34.v1"


def solve2(a, b):
    """Solve the 2x2 linear system a @ x = b via Cramer's rule."""
    d = a[0][0] * a[1][1] - a[0][1] * a[1][0]
    assert d != 0, "singular system"
    x = (b[0] * a[1][1] - a[0][1] * b[1]) / d
    y = (a[0][0] * b[1] - b[0] * a[1][0]) / d
    return [x, y]

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
    assert solve2([[2,1],[1,3]], [5,7]) == [1.6, 1.8]
    assert solve2([[1,0],[0,1]], [3,4]) == [3.0, 4.0]
    assert solve2([[3,2],[1,4]], [7,9]) == [1.0, 2.0]
    assert stdlib_only()
    print("mat_34 OK")


if __name__ == "__main__":
    main()
