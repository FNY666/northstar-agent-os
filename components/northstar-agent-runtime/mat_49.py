"""mat_49: Horizontal flip.

Mirror a matrix left-to-right.

Time complexity: O(m*n) time
Space complexity: O(m*n) auxiliary"""

import ast
import sys
MAT_49_VERSION = "mat-49.v1"


def flip_horizontal(m):
    """Return m mirrored left-to-right."""
    return [row[::-1] for row in m]

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
    assert flip_horizontal([[1,2],[3,4]]) == [[2,1],[4,3]]
    assert flip_horizontal([[1,2,3]]) == [[3,2,1]]
    assert flip_horizontal([[1],[2]]) == [[1],[2]]
    assert stdlib_only()
    print("mat_49 OK")


if __name__ == "__main__":
    main()
