"""mat_27: Sparse matrix check.

Check whether more than half of the elements are zero.

Time complexity: O(m*n) time
Space complexity: O(m*n) auxiliary"""

import ast
import sys
MAT_27_VERSION = "mat-27.v1"


def is_sparse(m):
    """Return True when more than half of the elements are zero."""
    flat = [x for row in m for x in row]
    return sum(1 for x in flat if x == 0) > len(flat) / 2

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
    assert is_sparse([[0,0,1],[0,0,0],[0,0,0]]) is True
    assert is_sparse([[1,2],[3,4]]) is False
    assert is_sparse([[0]]) is True
    assert stdlib_only()
    print("mat_27 OK")


if __name__ == "__main__":
    main()
