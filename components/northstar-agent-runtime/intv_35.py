"""intv_35: Count car fleets reaching the target (car_fleet).

Compute arrival times from the back; a slower car ahead forms a fleet.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_35 = "intv-35.v1"


def car_fleet(target, position, speed):
    """Number of fleets arriving at ``target``."""
    cars = sorted(zip(position, speed), reverse=True)
    fleets = 0
    slowest = -1.0
    for p, s in cars:
        t = (target - p) / s
        if t > slowest:
            fleets += 1
            slowest = t
    return fleets

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
    assert car_fleet(12, [10, 8, 0, 5, 3], [2, 4, 1, 1, 3]) == 3
    assert car_fleet(10, [3], [3]) == 1
    assert car_fleet(100, [0, 2, 4], [4, 2, 1]) == 1
    assert car_fleet(10, [6, 8], [3, 2]) == 2
    assert car_fleet(10, [], []) == 0
    assert stdlib_only()
    print("intv_35 OK")


if __name__ == "__main__":
    main()
