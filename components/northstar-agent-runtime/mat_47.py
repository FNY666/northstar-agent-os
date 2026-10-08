"""mat_47: Magic square check.

Check whether a square matrix is a magic square.

Time complexity: O(n^2) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_47_VERSION = "mat-47.v1"


def is_magic_square(m):
    """Return True iff rows, cols and both diagonals share one sum."""
    n = len(m)
    if n == 0 or any(len(r) != n for r in m):
        return False
    target = sum(m[0])
    if any(sum(r) != target for r in m):
        return False
    if any(sum(m[i][j] for i in range(n)) != target for j in range(n)):
        return False
    if sum(m[i][i] for i in range(n)) != target:
        return False
    return sum(m[i][n - 1 - i] for i in range(n)) == target

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
    assert is_magic_square([[8,1,6],[3,5,7],[4,9,2]]) is True
    assert is_magic_square([[1,2],[3,4]]) is False
    assert is_magic_square([[2,7,6],[9,5,1],[4,3,8]]) is True
    assert stdlib_only()
    print("mat_47 OK")


if __name__ == "__main__":
    main()
