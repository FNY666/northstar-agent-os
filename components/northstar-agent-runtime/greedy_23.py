"""greedy_23: Minimum refueling stops.

Drive past every reachable station, remembering its fuel in a max-heap; refuel from the largest when stuck.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_23_VERSION = "greedy-23.v1"


def min_refuel_stops(target, start_fuel, stations):
    """Return the minimum refuels to reach target, or -1 if impossible."""
    import heapq
    stations = sorted(stations)
    heap = []
    fuel = start_fuel
    i = 0
    stops = 0
    while fuel < target:
        while i < len(stations) and stations[i][0] <= fuel:
            heapq.heappush(heap, -stations[i][1])
            i += 1
        if not heap:
            return -1
        fuel += -heapq.heappop(heap)
        stops += 1
    return stops

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
    assert min_refuel_stops(1, 1, []) == 0
    assert min_refuel_stops(100, 1, [[10, 100]]) == -1
    assert min_refuel_stops(100, 10, [[10, 60], [20, 30], [30, 30], [60, 40]]) == 2
    assert min_refuel_stops(100, 50, [[50, 50]]) == 1
    assert stdlib_only()
    print("greedy_23 OK")


if __name__ == "__main__":
    main()
