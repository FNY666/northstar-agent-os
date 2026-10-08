"""greedy_28: Maximum units on a truck.

Load box types in decreasing units-per-box order, taking as many as fit.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_28_VERSION = "greedy-28.v1"


def max_units_truck(box_types, truck_size):
    """Return the maximum total units loadable onto the truck."""
    ordered = sorted(box_types, key=lambda b: b[1], reverse=True)
    total = 0
    for count, units in ordered:
        take = min(count, truck_size)
        total += take * units
        truck_size -= take
        if truck_size == 0:
            break
    return total

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
    assert max_units_truck([[1, 3], [2, 2], [3, 1]], 4) == 8
    assert max_units_truck([[5, 10], [2, 5], [4, 7], [3, 9]], 10) == 91
    assert max_units_truck([], 5) == 0
    assert max_units_truck([[1, 3]], 0) == 0
    assert stdlib_only()
    print("greedy_28 OK")


if __name__ == "__main__":
    main()
