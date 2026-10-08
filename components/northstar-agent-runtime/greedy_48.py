"""greedy_48: Two city scheduling.

Sort by (costA - costB); send the n people with the largest savings to city A.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_48_VERSION = "greedy-48.v1"


def two_city_cost(costs):
    """Return the minimum cost to send exactly half the people to each city."""
    n = len(costs) // 2
    base = sum(b for _a, b in costs)
    diffs = sorted(a - b for a, b in costs)
    return base + sum(diffs[:n])

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
    assert two_city_cost([[10, 20], [30, 200], [400, 50], [30, 20]]) == 110
    assert two_city_cost([[259, 770], [448, 54], [926, 667], [184, 139], [840, 118], [577, 469]]) == 1859
    assert two_city_cost([[10, 10], [10, 10]]) == 20
    assert two_city_cost([]) == 0
    assert stdlib_only()
    print("greedy_48 OK")


if __name__ == "__main__":
    main()
