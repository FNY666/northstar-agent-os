"""mat_20: Toeplitz matrix check.

Check whether every descending diagonal is constant.

Time complexity: O(m*n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_20_VERSION = "mat-20.v1"


def is_toeplitz(m):
    """Return True iff every descending diagonal of m is constant."""
    return all(m[i][j] == m[i - 1][j - 1]
               for i in range(1, len(m)) for j in range(1, len(m[0])))

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
    assert is_toeplitz([[1,2,3,4],[5,1,2,3],[9,5,1,2]]) is True
    assert is_toeplitz([[1,2],[2,2]]) is False
    assert is_toeplitz([[7]]) is True
    assert stdlib_only()
    print("mat_20 OK")


if __name__ == "__main__":
    main()
