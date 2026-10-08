"""mat_38: Count negatives.

Count the negative elements in a matrix.

Time complexity: O(m*n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_38_VERSION = "mat-38.v1"


def count_negatives(m):
    """Return the number of negative elements in m."""
    return sum(1 for row in m for x in row if x < 0)

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
    assert count_negatives([[4,3,2,-1],[3,2,1,-1],[1,1,-1,-2],[-1,-1,-2,-3]]) == 8
    assert count_negatives([[1,2],[3,4]]) == 0
    assert count_negatives([[-1,-2],[-3,-4]]) == 4
    assert stdlib_only()
    print("mat_38 OK")


if __name__ == "__main__":
    main()
