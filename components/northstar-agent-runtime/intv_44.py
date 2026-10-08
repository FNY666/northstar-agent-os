"""intv_44: Divide intervals into minimum groups (min_groups).

Sweep line: each start needs a new group only when all are busy.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

import heapq
INTV_44 = "intv-44.v1"


def min_groups(intervals):
    """Minimum groups so no group has overlapping intervals."""
    ivs = sorted(intervals, key=lambda x: x[0])
    heap = []
    for s, e in ivs:
        if heap and heap[0] < s:
            heapq.heappop(heap)
        heapq.heappush(heap, e)
    return len(heap)

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
    assert min_groups([(5, 10), (6, 8), (1, 5), (2, 3), (1, 10)]) == 3
    assert min_groups([(1, 3), (5, 6), (8, 10), (11, 13)]) == 1
    assert min_groups([(1, 2)]) == 1
    assert min_groups([(1, 5), (2, 6), (3, 7)]) == 3
    assert min_groups([]) == 0
    assert stdlib_only()
    print("intv_44 OK")


if __name__ == "__main__":
    main()
