"""psum_07: 2D Difference Array

Rectangle addition in O(1); materialize with a 2D prefix pass.

Time complexity: O(1) update, O(r*c) materialize
Space complexity: O(r*c)"""

import ast
import sys
PSUM_07_VERSION = "psum-07.v1"


def build(r, c):
    return [[0] * (c + 1) for _ in range(r + 1)]


def rect_add(d, r1, c1, r2, c2, v):
    d[r1][c1] += v
    d[r1][c2 + 1] -= v
    d[r2 + 1][c1] -= v
    d[r2 + 1][c2 + 1] += v


def materialize(d, r, c):
    out = [[0] * c for _ in range(r)]
    for i in range(r):
        for j in range(c):
            up = out[i - 1][j] if i else 0
            lf = out[i][j - 1] if j else 0
            dg = out[i - 1][j - 1] if i and j else 0
            out[i][j] = d[i][j] + up + lf - dg
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
    d = build(2, 2)
    rect_add(d, 0, 0, 1, 1, 3)
    assert materialize(d, 2, 2) == [[3, 3], [3, 3]]
    d = build(3, 3)
    rect_add(d, 1, 1, 2, 2, 5)
    assert materialize(d, 3, 3) == [[0, 0, 0], [0, 5, 5], [0, 5, 5]]
    d = build(1, 1)
    assert materialize(d, 1, 1) == [[0]]
    assert stdlib_only()
    print("psum_07 OK")


if __name__ == "__main__":
    main()
