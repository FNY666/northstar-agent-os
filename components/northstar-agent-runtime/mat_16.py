"""mat_16: Diagonal traversal.

Traverse a matrix along diagonals, alternating direction (LeetCode 498).

Time complexity: O(m*n) time
Space complexity: O(m*n) auxiliary"""

import ast
import sys
MAT_16_VERSION = "mat-16.v1"


def diag_traverse(m):
    """Return elements along anti-diagonals with alternating direction."""
    if not m or not m[0]:
        return []
    rows, cols = len(m), len(m[0])
    out = []
    for d in range(rows + cols - 1):
        diag = []
        r = max(0, d - cols + 1)
        while r < rows and d - r >= 0:
            c = d - r
            if c < cols:
                diag.append(m[r][c])
            r += 1
        if d % 2 == 0:
            diag.reverse()
        out.extend(diag)
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
    assert diag_traverse([[1,2,3],[4,5,6],[7,8,9]]) == [1,2,4,7,5,3,6,8,9]
    assert diag_traverse([[1,2],[3,4]]) == [1,2,3,4]
    assert diag_traverse([[7]]) == [7]
    assert stdlib_only()
    print("mat_16 OK")


if __name__ == "__main__":
    main()
