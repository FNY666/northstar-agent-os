"""mat_22: Skew-symmetric matrix check.

Check whether a square matrix equals the negation of its transpose.

Time complexity: O(n^2) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_22_VERSION = "mat-22.v1"


def is_skew_symmetric(m):
    """Return True iff m[i][j] == -m[j][i] for all i, j."""
    n = len(m)
    if n == 0 or any(len(r) != n for r in m):
        return False
    return all(m[i][j] == -m[j][i] for i in range(n) for j in range(n))

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
    assert is_skew_symmetric([[0,2],[-2,0]]) is True
    assert is_skew_symmetric([[0,2],[2,0]]) is False
    assert is_skew_symmetric([[0]]) is True
    assert stdlib_only()
    print("mat_22 OK")


if __name__ == "__main__":
    main()
