"""mat_28: Matrix reshape.

Reshape a matrix to new dimensions preserving row-major order.

Time complexity: O(m*n) time
Space complexity: O(m*n) auxiliary"""

import ast
import sys
MAT_28_VERSION = "mat-28.v1"


def reshape(m, rows, cols):
    """Reshape m to a rows x cols matrix in row-major order."""
    flat = [x for row in m for x in row]
    assert len(flat) == rows * cols, "element count mismatch"
    return [flat[i * cols:(i + 1) * cols] for i in range(rows)]

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
    assert reshape([[1,2,3],[4,5,6]], 3, 2) == [[1,2],[3,4],[5,6]]
    assert reshape([[1,2],[3,4]], 1, 4) == [[1,2,3,4]]
    assert reshape([[1,2,3,4]], 2, 2) == [[1,2],[3,4]]
    assert stdlib_only()
    print("mat_28 OK")


if __name__ == "__main__":
    main()
