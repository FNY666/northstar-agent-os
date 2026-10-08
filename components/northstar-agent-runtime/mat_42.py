"""mat_42: Upper triangle sum.

Sum the elements strictly above the main diagonal.

Time complexity: O(n^2) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_42_VERSION = "mat-42.v1"


def upper_tri_sum(m):
    """Return the sum of elements strictly above the main diagonal."""
    return sum(m[i][j] for i in range(len(m))
               for j in range(len(m[0])) if j > i)

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
    assert upper_tri_sum([[1,2,3],[4,5,6],[7,8,9]]) == 11
    assert upper_tri_sum([[1,2],[3,4]]) == 2
    assert upper_tri_sum([[5]]) == 0
    assert stdlib_only()
    print("mat_42 OK")


if __name__ == "__main__":
    main()
