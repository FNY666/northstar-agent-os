"""psum_21: 2D Count of Ones

Summed-area table over a binary matrix counts ones in any rectangle.

Time complexity: O(r*c) build, O(1) query
Space complexity: O(r*c)"""

import ast
import sys
PSUM_21_VERSION = "psum-21.v1"


def build(m):
    r = len(m)
    c = len(m[0]) if r else 0
    p = [[0] * (c + 1) for _ in range(r + 1)]
    for i in range(r):
        for j in range(c):
            p[i + 1][j + 1] = m[i][j] + p[i][j + 1] + p[i + 1][j] - p[i][j]
    return p


def count_ones(p, r1, c1, r2, c2):
    return p[r2 + 1][c2 + 1] - p[r1][c2 + 1] - p[r2 + 1][c1] + p[r1][c1]

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
    p = build([[1, 0, 1], [0, 1, 0], [1, 1, 0]])
    assert count_ones(p, 0, 0, 2, 2) == 5
    assert count_ones(p, 0, 0, 1, 1) == 2
    assert count_ones(p, 2, 2, 2, 2) == 0
    assert count_ones(p, 0, 2, 0, 2) == 1
    assert stdlib_only()
    print("psum_21 OK")


if __name__ == "__main__":
    main()
