"""intv_11: Check capacity along a route (car_pooling).

Difference array: add passengers at start, remove at end, prefix-scan.

Time complexity: O(n + m) time
Space complexity: O(m) auxiliary
"""

import ast
import sys

INTV_11 = "intv-11.v1"


def car_pooling(trips, capacity):
    """True when ``capacity`` seats suffice for all ``trips``."""
    stops = [0] * 1001
    for num, s, e in trips:
        stops[s] += num
        stops[e] -= num
    cur = 0
    for v in stops:
        cur += v
        if cur > capacity:
            return False
    return True

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
    assert car_pooling([(2, 1, 5), (3, 3, 7)], 4) is False
    assert car_pooling([(2, 1, 5), (3, 3, 7)], 5) is True
    assert car_pooling([(2, 1, 5), (3, 5, 7)], 3) is True
    assert car_pooling([], 10) is True
    assert car_pooling([(3, 2, 7), (3, 7, 9), (8, 3, 9)], 11) is True
    assert stdlib_only()
    print("intv_11 OK")


if __name__ == "__main__":
    main()
