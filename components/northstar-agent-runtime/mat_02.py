"""mat_02: Matrix subtraction.

Subtract the second matrix from the first, element-wise.

Time complexity: O(m*n) time
Space complexity: O(m*n) auxiliary"""

import ast
import sys
MAT_02_VERSION = "mat-02.v1"


def mat_sub(a, b):
    """Return the element-wise difference a - b of two same-shaped matrices."""
    return [[x - y for x, y in zip(ra, rb)] for ra, rb in zip(a, b)]

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
    assert mat_sub([[5,6],[7,8]], [[1,2],[3,4]]) == [[4,4],[4,4]]
    assert mat_sub([[1]], [[1]]) == [[0]]
    assert mat_sub([[0,0],[0,0]], [[1,2],[3,4]]) == [[-1,-2],[-3,-4]]
    assert stdlib_only()
    print("mat_02 OK")


if __name__ == "__main__":
    main()
