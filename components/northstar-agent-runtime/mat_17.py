"""mat_17: Zigzag row traversal.

Read rows left-to-right, then right-to-left, alternating.

Time complexity: O(m*n) time
Space complexity: O(m*n) auxiliary"""

import ast
import sys
MAT_17_VERSION = "mat-17.v1"


def zigzag_rows(m):
    """Return elements reading even rows left-to-right and odd rows right-to-left."""
    out = []
    for i, row in enumerate(m):
        out.extend(row if i % 2 == 0 else row[::-1])
    return out

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
    assert zigzag_rows([[1,2,3],[4,5,6]]) == [1,2,3,6,5,4]
    assert zigzag_rows([[1,2],[3,4],[5,6]]) == [1,2,4,3,5,6]
    assert zigzag_rows([[9]]) == [9]
    assert stdlib_only()
    print("mat_17 OK")


if __name__ == "__main__":
    main()
