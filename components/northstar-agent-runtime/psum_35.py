"""psum_35: 3D Prefix Sum

Inclusion-exclusion over 8 corners answers any 3D box sum in O(1).

Time complexity: O(x*y*z) build, O(1) query
Space complexity: O(x*y*z)"""

import ast
import sys
PSUM_35_VERSION = "psum-35.v1"


def build(cube):
    x = len(cube)
    y = len(cube[0])
    z = len(cube[0][0])
    p = [[[0] * (z + 1) for _ in range(y + 1)] for _ in range(x + 1)]
    for i in range(x):
        for j in range(y):
            for k in range(z):
                p[i + 1][j + 1][k + 1] = (
                    cube[i][j][k]
                    + p[i][j + 1][k + 1] + p[i + 1][j][k + 1] + p[i + 1][j + 1][k]
                    - p[i][j][k + 1] - p[i][j + 1][k] - p[i + 1][j][k]
                    + p[i][j][k]
                )
    return p


def box(p, x1, y1, z1, x2, y2, z2):
    return (
        p[x2 + 1][y2 + 1][z2 + 1]
        - p[x1][y2 + 1][z2 + 1] - p[x2 + 1][y1][z2 + 1] - p[x2 + 1][y2 + 1][z1]
        + p[x1][y1][z2 + 1] + p[x1][y2 + 1][z1] + p[x2 + 1][y1][z1]
        - p[x1][y1][z1]
    )

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
    cube = [[[1, 1], [1, 1]], [[1, 1], [1, 1]]]
    p = build(cube)
    assert box(p, 0, 0, 0, 1, 1, 1) == 8
    assert box(p, 0, 0, 0, 0, 0, 0) == 1
    assert box(p, 1, 1, 1, 1, 1, 1) == 1
    assert box(p, 0, 0, 0, 1, 0, 1) == 4
    assert stdlib_only()
    print("psum_35 OK")


if __name__ == "__main__":
    main()
