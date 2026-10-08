"""mat_41: Anti-diagonal sum.

Sum the elements on the anti-diagonal of a square matrix.

Time complexity: O(n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_41_VERSION = "mat-41.v1"


def anti_diag_sum(m):
    """Return the sum of the anti-diagonal elements."""
    n = len(m)
    return sum(m[i][n - 1 - i] for i in range(n))

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
    assert anti_diag_sum([[1,2],[3,4]]) == 5
    assert anti_diag_sum([[1,2,3],[4,5,6],[7,8,9]]) == 15
    assert anti_diag_sum([[7]]) == 7
    assert stdlib_only()
    print("mat_41 OK")


if __name__ == "__main__":
    main()
