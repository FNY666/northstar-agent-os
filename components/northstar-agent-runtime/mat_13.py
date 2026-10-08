"""mat_13: Rotate 90 degrees counter-clockwise.

Rotate a square matrix 90 degrees counter-clockwise.

Time complexity: O(n^2) time
Space complexity: O(n^2) auxiliary"""

import ast
import sys
MAT_13_VERSION = "mat-13.v1"


def rotate90_ccw(m):
    """Return m rotated 90 degrees counter-clockwise."""
    return [list(row) for row in zip(*m)][::-1]

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
    assert rotate90_ccw([[1,2],[3,4]]) == [[2,4],[1,3]]
    assert rotate90_ccw([[1,2,3],[4,5,6],[7,8,9]]) == [[3,6,9],[2,5,8],[1,4,7]]
    assert rotate90_ccw([[5]]) == [[5]]
    assert stdlib_only()
    print("mat_13 OK")


if __name__ == "__main__":
    main()
