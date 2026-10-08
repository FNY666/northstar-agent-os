"""intv_45: Maximum events that can be attended (max_events).

Sweep days; heap of end days, attend the one ending soonest.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

import heapq
INTV_45 = "intv-45.v1"


def max_events(events):
    """Max events attendable (one per day within [start, end])."""
    events = sorted(events)
    heap = []
    i = 0
    n = len(events)
    day = 0
    attended = 0
    while i < n or heap:
        if not heap:
            day = max(day, events[i][0])
        while i < n and events[i][0] <= day:
            heapq.heappush(heap, events[i][1])
            i += 1
        heapq.heappop(heap)
        attended += 1
        day += 1
        while heap and heap[0] < day:
            heapq.heappop(heap)
    return attended

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
    assert max_events([[1, 2], [2, 3], [3, 4]]) == 3
    assert max_events([[1, 2], [2, 3], [3, 4], [1, 2]]) == 4
    assert max_events([[1, 4], [4, 4], [2, 2], [3, 4], [1, 1]]) == 4
    assert max_events([[1, 1]]) == 1
    assert max_events([]) == 0
    assert stdlib_only()
    print("intv_45 OK")


if __name__ == "__main__":
    main()
