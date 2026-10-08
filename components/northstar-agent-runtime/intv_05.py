"""intv_05: Minimum meeting rooms required (min_rooms).

Sweep line: +1 at start, -1 at end; track the peak.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_05 = "intv-05.v1"


def min_rooms(intervals):
    """Return the minimum number of rooms so all meetings fit."""
    if not intervals:
        return 0
    events = []
    for s, e in intervals:
        events.append((s, 1)); events.append((e, -1))
    events.sort(key=lambda x: (x[0], x[1]))
    cur = best = 0
    for _, d in events:
        cur += d
        if cur > best:
            best = cur
    return best

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
    assert min_rooms([(0, 30), (5, 10), (15, 20)]) == 2
    assert min_rooms([(7, 10), (2, 4)]) == 1
    assert min_rooms([]) == 0
    assert min_rooms([(1, 5), (8, 9), (8, 9)]) == 2
    assert min_rooms([(1, 2), (2, 3), (3, 4)]) == 1
    assert stdlib_only()
    print("intv_05 OK")


if __name__ == "__main__":
    main()
