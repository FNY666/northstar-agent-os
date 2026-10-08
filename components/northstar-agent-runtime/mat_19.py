"""mat_19: Spiral matrix generation.

Generate an n x n matrix filled 1..n*n in clockwise spiral order.

Time complexity: O(n^2) time
Space complexity: O(n^2) auxiliary"""

import ast
import sys
MAT_19_VERSION = "mat-19.v1"


def spiral_gen(n):
    """Return an n x n matrix filled 1..n*n in clockwise spiral order."""
    m = [[0] * n for _ in range(n)]
    top, bottom, left, right = 0, n - 1, 0, n - 1
    v = 1
    while top <= bottom and left <= right:
        for j in range(left, right + 1):
            m[top][j] = v; v += 1
        top += 1
        for i in range(top, bottom + 1):
            m[i][right] = v; v += 1
        right -= 1
        if top <= bottom:
            for j in range(right, left - 1, -1):
                m[bottom][j] = v; v += 1
            bottom -= 1
        if left <= right:
            for i in range(bottom, top - 1, -1):
                m[i][left] = v; v += 1
            left += 1
    return m

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
    assert spiral_gen(3) == [[1,2,3],[8,9,4],[7,6,5]]
    assert spiral_gen(1) == [[1]]
    assert spiral_gen(2) == [[1,2],[4,3]]
    assert stdlib_only()
    print("mat_19 OK")


if __name__ == "__main__":
    main()
