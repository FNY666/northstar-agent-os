"""greedy_02: Fractional knapsack.

Take items in decreasing value/weight ratio, splitting the last item as needed.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_02_VERSION = "greedy-02.v1"


def fractional_knapsack(items, capacity):
    """Return the maximum value obtainable.

    items: iterable of (value, weight) pairs. Fractions of items may be taken.
    """
    if capacity <= 0:
        return 0.0
    ordered = sorted(items, key=lambda iv: (iv[0] / iv[1]) if iv[1] else 0.0, reverse=True)
    total = 0.0
    for value, weight in ordered:
        if capacity <= 0:
            break
        if weight <= 0:
            continue
        take = min(weight, capacity)
        total += value * (take / weight)
        capacity -= take
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
    assert fractional_knapsack([(60, 10), (100, 20), (120, 30)], 50) == 240.0
    assert fractional_knapsack([], 10) == 0.0
    assert fractional_knapsack([(60, 10)], 0) == 0.0
    assert abs(fractional_knapsack([(60, 10), (100, 20)], 15) - 85.0) < 1e-9
    assert stdlib_only()
    print("greedy_02 OK")


if __name__ == "__main__":
    main()
