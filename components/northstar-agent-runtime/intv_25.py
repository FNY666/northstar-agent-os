"""intv_25: Range addition max value (range_addition).

Difference array over the range, prefix-scan for the max.

Time complexity: O(n + m) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_25 = "intv-25.v1"


def range_addition(length, updates):
    """Apply [start, end, inc] updates; return the resulting array."""
    diff = [0] * (length + 1)
    for s, e, inc in updates:
        diff[s] += inc
        if e + 1 < len(diff):
            diff[e + 1] -= inc
    res = []
    cur = 0
    for i in range(length):
        cur += diff[i]
        res.append(cur)
    return res

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
    assert range_addition(5, [(1, 3, 2), (2, 4, 3), (0, 2, -2)]) == [-2, 0, 3, 5, 3]
    assert range_addition(3, []) == [0, 0, 0]
    assert range_addition(1, [(0, 0, 7)]) == [7]
    assert range_addition(4, [(0, 3, 1)]) == [1, 1, 1, 1]
    assert range_addition(2, [(0, 0, 5), (1, 1, 6)]) == [5, 6]
    assert stdlib_only()
    print("intv_25 OK")


if __name__ == "__main__":
    main()
