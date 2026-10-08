"""psum_36: Diagonal Prefix Sum

NW-SE diagonal accumulation answers diagonal range sums in O(1).

Time complexity: O(r*c) build, O(1) query
Space complexity: O(r*c)"""

import ast
import sys
PSUM_36_VERSION = "psum-36.v1"


def build(m):
    r = len(m)
    c = len(m[0]) if r else 0
    p = [[0] * c for _ in range(r)]
    for i in range(r):
        for j in range(c):
            p[i][j] = m[i][j] + (p[i - 1][j - 1] if i and j else 0)
    return p


def diag_sum(p, r1, c1, r2, c2):
    """Sum along the diagonal (r1,c1)->(r2,c2); requires r2-r1 == c2-c1."""
    return p[r2][c2] - (p[r1 - 1][c1 - 1] if r1 and c1 else 0)

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
    p = build([[1, 2, 3], [4, 5, 6], [7, 8, 9]])
    assert diag_sum(p, 0, 0, 2, 2) == 15
    assert diag_sum(p, 1, 1, 2, 2) == 14
    assert diag_sum(p, 0, 1, 1, 2) == 8
    assert diag_sum(p, 2, 0, 2, 0) == 7
    assert stdlib_only()
    print("psum_36 OK")


if __name__ == "__main__":
    main()
