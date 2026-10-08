"""mat_12: Rotate 90 degrees clockwise.

Rotate a square matrix 90 degrees clockwise.

Time complexity: O(n^2) time
Space complexity: O(n^2) auxiliary"""

import ast
import sys
MAT_12_VERSION = "mat-12.v1"


def rotate90_cw(m):
    """Return m rotated 90 degrees clockwise."""
    return [list(row) for row in zip(*m[::-1])]

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
    assert rotate90_cw([[1,2],[3,4]]) == [[3,1],[4,2]]
    assert rotate90_cw([[1,2,3],[4,5,6],[7,8,9]]) == [[7,4,1],[8,5,2],[9,6,3]]
    assert rotate90_cw([[5]]) == [[5]]
    assert stdlib_only()
    print("mat_12 OK")


if __name__ == "__main__":
    main()
