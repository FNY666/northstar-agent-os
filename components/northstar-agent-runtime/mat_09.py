"""mat_09: Matrix equality.

Check whether two matrices are element-wise equal.

Time complexity: O(m*n) time
Space complexity: O(1) auxiliary"""

import ast
import sys
MAT_09_VERSION = "mat-09.v1"


def mat_equal(a, b):
    """Return True iff a and b have the same shape and elements."""
    return (len(a) == len(b)
            and all(len(ra) == len(rb) for ra, rb in zip(a, b))
            and all(x == y for ra, rb in zip(a, b)
                    for x, y in zip(ra, rb)))

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
    assert mat_equal([[1,2],[3,4]], [[1,2],[3,4]]) is True
    assert mat_equal([[1,2],[3,4]], [[1,2],[3,5]]) is False
    assert mat_equal([[1,2]], [[1],[2]]) is False
    assert stdlib_only()
    print("mat_09 OK")


if __name__ == "__main__":
    main()
