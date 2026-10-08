"""greedy_29: Minimum cost to connect sticks.

Always merge the two shortest sticks with a min-heap (Huffman-style).

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_29_VERSION = "greedy-29.v1"


def connect_sticks(sticks):
    """Return the minimum total cost to connect all sticks into one."""
    import heapq
    if len(sticks) <= 1:
        return 0
    heap = list(sticks)
    heapq.heapify(heap)
    cost = 0
    while len(heap) > 1:
        a = heapq.heappop(heap)
        b = heapq.heappop(heap)
        cost += a + b
        heapq.heappush(heap, a + b)
    return cost

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
    assert connect_sticks([2, 4, 3]) == 14
    assert connect_sticks([1, 8, 3, 5]) == 30
    assert connect_sticks([]) == 0
    assert connect_sticks([5]) == 0
    assert stdlib_only()
    print("greedy_29 OK")


if __name__ == "__main__":
    main()
