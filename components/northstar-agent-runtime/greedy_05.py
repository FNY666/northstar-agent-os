"""greedy_05: Maximum meetings in one room.

Classic meeting-room variant: sort by end time, take a meeting when its start is after the last chosen end.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_05_VERSION = "greedy-05.v1"


def max_meetings(start, end):
    """Return (count, [1-based meeting numbers]) of the max non-overlapping set."""
    order = sorted(range(len(start)), key=lambda i: end[i])
    chosen = []
    last_end = float("-inf")
    for i in order:
        if start[i] > last_end:
            chosen.append(i + 1)
            last_end = end[i]
    return len(chosen), chosen

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
    assert max_meetings([1, 3, 0, 5, 8, 5], [2, 4, 6, 7, 9, 9]) == (4, [1, 2, 4, 5])
    assert max_meetings([], []) == (0, [])
    assert max_meetings([1], [2]) == (1, [1])
    assert max_meetings([1, 2], [2, 3]) == (1, [1])
    assert stdlib_only()
    print("greedy_05 OK")


if __name__ == "__main__":
    main()
