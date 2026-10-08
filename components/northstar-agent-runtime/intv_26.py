"""intv_26: Skyline key points from buildings (skyline).

Sweep x with a max-heap of active heights; emit when the max changes.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

import heapq
INTV_26 = "intv-26.v1"


def skyline(buildings):
    """Return the skyline as [x, height] key points."""
    events = []
    for l, r, h in buildings:
        events.append((l, -h, r)); events.append((r, 0, 0))
    events.sort()
    res = []
    live = [(0, float("inf"))]
    for x, nh, r in events:
        while live[0][1] <= x:
            heapq.heappop(live)
        if nh:
            heapq.heappush(live, (nh, r))
        cur_h = -live[0][0]
        if not res or res[-1][1] != cur_h:
            res.append([x, cur_h])
    return res

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
    assert skyline([(2, 9, 10), (3, 7, 15), (5, 12, 12), (15, 20, 10), (19, 24, 8)]) == [[2, 10], [3, 15], [7, 12], [12, 0], [15, 10], [20, 8], [24, 0]]
    assert skyline([(0, 2, 3), (2, 5, 3)]) == [[0, 3], [5, 0]]
    assert skyline([]) == []
    assert skyline([(1, 2, 1)]) == [[1, 1], [2, 0]]
    assert skyline([(1, 3, 3), (2, 4, 4)]) == [[1, 3], [2, 4], [4, 0]]
    assert stdlib_only()
    print("intv_26 OK")


if __name__ == "__main__":
    main()
