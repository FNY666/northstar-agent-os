"""mat_18: Border sum.

Sum the elements on the outer border of a matrix.

Time complexity: O(m*n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_18_VERSION = "mat-18.v1"


def border_sum(m):
    """Return the sum of the elements on the outer border of m."""
    rows, cols = len(m), len(m[0])
    if rows == 1:
        return sum(m[0])
    if cols == 1:
        return sum(r[0] for r in m)
    return (sum(m[0]) + sum(m[-1])
            + sum(m[i][0] for i in range(1, rows - 1))
            + sum(m[i][-1] for i in range(1, rows - 1)))

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
    assert border_sum([[1,2,3],[4,5,6],[7,8,9]]) == 40
    assert border_sum([[1,2],[3,4]]) == 10
    assert border_sum([[5]]) == 5
    assert stdlib_only()
    print("mat_18 OK")


if __name__ == "__main__":
    main()
