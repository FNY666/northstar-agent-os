"""greedy_30: Furthest building you can reach.

Use ladders on the largest climbs seen so far; pay bricks for the rest via a min-heap.

Time complexity: O(n log L) time
Space complexity: O(L) auxiliary
"""

import ast
import sys
GREEDY_30_VERSION = "greedy-30.v1"


def furthest_building(heights, bricks, ladders):
    """Return the furthest reachable building index."""
    import heapq
    heap = []
    for i in range(len(heights) - 1):
        diff = heights[i + 1] - heights[i]
        if diff <= 0:
            continue
        heapq.heappush(heap, diff)
        if len(heap) > ladders:
            bricks -= heapq.heappop(heap)
        if bricks < 0:
            return i
    return len(heights) - 1

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
    assert furthest_building([4, 2, 7, 6, 9, 14, 12], 5, 1) == 4
    assert furthest_building([4, 12, 2, 7, 3, 18, 20, 3, 19], 10, 2) == 7
    assert furthest_building([1, 2], 0, 0) == 0
    assert furthest_building([1, 2, 3], 10, 0) == 2
    assert stdlib_only()
    print("greedy_30 OK")


if __name__ == "__main__":
    main()
