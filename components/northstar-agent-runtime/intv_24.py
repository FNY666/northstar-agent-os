"""intv_24: Fewest bricks crossed by a vertical line (brick_wall).

Count interior edge positions across rows; the best line uses the max.

Time complexity: O(r * c) time
Space complexity: O(r * c) auxiliary
"""

import ast
import sys

INTV_24 = "intv-24.v1"


def brick_wall(wall):
    """Minimum bricks a vertical line must cross."""
    from collections import Counter
    edges = Counter()
    for row in wall:
        pos = 0
        for b in row[:-1]:
            pos += b
            edges[pos] += 1
    if not edges:
        return len(wall)
    return len(wall) - max(edges.values())

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
    assert brick_wall([[1, 2, 2, 1], [3, 1, 2], [1, 3, 2], [2, 4], [3, 1, 2], [1, 3, 1, 1]]) == 2
    assert brick_wall([[1], [1], [1]]) == 3
    assert brick_wall([[1, 1], [1, 1]]) == 1
    assert brick_wall([[2, 2], [2, 2]]) == 2
    assert brick_wall([[1, 2], [2, 1]]) == 1
    assert stdlib_only()
    print("intv_24 OK")


if __name__ == "__main__":
    main()
