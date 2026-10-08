"""greedy_22: Boats to save people.

Pair the heaviest remaining person with the lightest one that still fits.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_22_VERSION = "greedy-22.v1"


def num_boats(people, limit):
    """Return the minimum number of boats (at most two people each)."""
    people = sorted(people)
    i = 0
    j = len(people) - 1
    boats = 0
    while i <= j:
        if people[i] + people[j] <= limit:
            i += 1
        j -= 1
        boats += 1
    return boats

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
    assert num_boats([1, 2], 3) == 1
    assert num_boats([3, 2, 2, 1], 3) == 3
    assert num_boats([], 5) == 0
    assert num_boats([3, 5, 3, 4], 5) == 4
    assert stdlib_only()
    print("greedy_22 OK")


if __name__ == "__main__":
    main()
