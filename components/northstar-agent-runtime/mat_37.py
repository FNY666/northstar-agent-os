"""mat_37: Argmax position.

Find the (row, col) position of the maximum element.

Time complexity: O(m*n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_37_VERSION = "mat-37.v1"


def argmax_pos(m):
    """Return the (i, j) position of the first maximum element."""
    bi, bj, bv = 0, 0, m[0][0]
    for i, row in enumerate(m):
        for j, v in enumerate(row):
            if v > bv:
                bi, bj, bv = i, j, v
    return (bi, bj)

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
    assert argmax_pos([[1,5],[9,2]]) == (1,0)
    assert argmax_pos([[9,5],[1,2]]) == (0,0)
    assert argmax_pos([[-5,-1],[-9,-2]]) == (0,1)
    assert stdlib_only()
    print("mat_37 OK")


if __name__ == "__main__":
    main()
