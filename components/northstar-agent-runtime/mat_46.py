"""mat_46: Saddle point.

Find an element that is the row minimum and column maximum.

Time complexity: O(m*n*(m+n)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_46_VERSION = "mat-46.v1"


def saddle_point(m):
    """Return (i, j) of a saddle point, or None if there is none."""
    rows, cols = len(m), len(m[0])
    for i in range(rows):
        j = min(range(cols), key=lambda c: m[i][c])
        if all(m[i][j] >= m[r][j] for r in range(rows)):
            return (i, j)
    return None

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
    assert saddle_point([[1,2],[0,3]]) == (0,0)
    assert saddle_point([[3,1,2],[4,5,6]]) == (1,0)
    assert saddle_point([[1,3],[2,0]]) is None
    assert stdlib_only()
    print("mat_46 OK")


if __name__ == "__main__":
    main()
