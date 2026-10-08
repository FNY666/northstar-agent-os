"""greedy_46: Minimum cost to move chips.

Moving by 2 is free, so only parity matters: move the smaller parity group.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_46_VERSION = "greedy-46.v1"


def min_cost_move_chips(position):
    """Return the minimum cost to gather all chips at one position."""
    even = sum(1 for p in position if p % 2 == 0)
    return min(even, len(position) - even)

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
    assert min_cost_move_chips([1, 2, 3]) == 1
    assert min_cost_move_chips([2, 2, 2, 3, 3]) == 2
    assert min_cost_move_chips([]) == 0
    assert min_cost_move_chips([1, 3, 5]) == 0
    assert stdlib_only()
    print("greedy_46 OK")


if __name__ == "__main__":
    main()
