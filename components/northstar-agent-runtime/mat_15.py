"""mat_15: Spiral order traversal.

Read matrix elements in clockwise spiral order.

Time complexity: O(m*n) time
Space complexity: O(m*n) auxiliary"""

import ast
import sys
MAT_15_VERSION = "mat-15.v1"


def spiral_order(m):
    """Return the elements of m in clockwise spiral order."""
    out = []
    if not m or not m[0]:
        return out
    top, bottom = 0, len(m) - 1
    left, right = 0, len(m[0]) - 1
    while top <= bottom and left <= right:
        for j in range(left, right + 1):
            out.append(m[top][j])
        top += 1
        for i in range(top, bottom + 1):
            out.append(m[i][right])
        right -= 1
        if top <= bottom:
            for j in range(right, left - 1, -1):
                out.append(m[bottom][j])
            bottom -= 1
        if left <= right:
            for i in range(bottom, top - 1, -1):
                out.append(m[i][left])
            left += 1
    return out

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
    assert spiral_order([[1,2,3],[4,5,6],[7,8,9]]) == [1,2,3,6,9,8,7,4,5]
    assert spiral_order([[1,2],[3,4]]) == [1,2,4,3]
    assert spiral_order([[1,2,3],[4,5,6]]) == [1,2,3,6,5,4]
    assert stdlib_only()
    print("mat_15 OK")


if __name__ == "__main__":
    main()
