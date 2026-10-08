"""greedy_06: Gas station circuit.

If total gas covers total cost, the greedy restart scan finds the unique feasible start.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_06_VERSION = "greedy-06.v1"


def gas_station(gas, cost):
    """Return the starting station index for a full circuit, or -1 if impossible."""
    if sum(gas) < sum(cost):
        return -1
    start = 0
    tank = 0
    for i in range(len(gas)):
        tank += gas[i] - cost[i]
        if tank < 0:
            start = i + 1
            tank = 0
    return start

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
    assert gas_station([1, 2, 3, 4, 5], [3, 4, 5, 1, 2]) == 3
    assert gas_station([2, 3, 4], [3, 4, 3]) == -1
    assert gas_station([5], [4]) == 0
    assert gas_station([3], [5]) == -1
    assert stdlib_only()
    print("greedy_06 OK")


if __name__ == "__main__":
    main()
