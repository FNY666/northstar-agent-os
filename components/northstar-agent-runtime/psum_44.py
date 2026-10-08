"""psum_44: 2D Prefix Maximum

2D prefix max answers the max over any origin-anchored rectangle in O(1).

Time complexity: O(r*c) build, O(1) query
Space complexity: O(r*c)"""

import ast
import sys
PSUM_44_VERSION = "psum-44.v1"


def build(m):
    r = len(m)
    c = len(m[0]) if r else 0
    p = [[0] * (c + 1) for _ in range(r + 1)]
    for i in range(r):
        for j in range(c):
            p[i + 1][j + 1] = max(m[i][j], p[i][j + 1], p[i + 1][j])
    return p


def rect_max_origin(p, r, c):
    """Max over m[0..r][0..c]."""
    return p[r + 1][c + 1]

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
    p = build([[1, 5], [3, 2]])
    assert rect_max_origin(p, 1, 1) == 5
    assert rect_max_origin(p, 0, 0) == 1
    assert rect_max_origin(p, 1, 0) == 3
    assert rect_max_origin(p, 0, 1) == 5
    assert stdlib_only()
    print("psum_44 OK")


if __name__ == "__main__":
    main()
