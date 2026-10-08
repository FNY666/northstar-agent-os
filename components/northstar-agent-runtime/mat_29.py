"""mat_29: Matrix flatten.

Flatten a matrix to a row-major list.

Time complexity: O(m*n) time
Space complexity: O(m*n) auxiliary"""

import ast
import sys
MAT_29_VERSION = "mat-29.v1"


def flatten(m):
    """Return the row-major flattening of matrix m."""
    return [x for row in m for x in row]

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
    assert flatten([[1,2],[3,4]]) == [1,2,3,4]
    assert flatten([[1,2,3],[4,5,6]]) == [1,2,3,4,5,6]
    assert flatten([[7]]) == [7]
    assert stdlib_only()
    print("mat_29 OK")


if __name__ == "__main__":
    main()
