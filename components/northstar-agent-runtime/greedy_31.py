"""greedy_31: IPO (maximize capital).

Repeatedly take the most profitable affordable project using a max-heap.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_31_VERSION = "greedy-31.v1"


def maximize_capital(k, w, profits, capital):
    """Return the maximum capital after at most k projects."""
    import heapq
    projects = sorted(zip(capital, profits))
    heap = []
    i = 0
    for _ in range(k):
        while i < len(projects) and projects[i][0] <= w:
            heapq.heappush(heap, -projects[i][1])
            i += 1
        if not heap:
            break
        w += -heapq.heappop(heap)
    return w

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
    assert maximize_capital(2, 0, [1, 2, 3], [0, 1, 1]) == 4
    assert maximize_capital(3, 0, [1, 2, 3], [0, 1, 2]) == 6
    assert maximize_capital(1, 0, [5], [10]) == 0
    assert maximize_capital(0, 7, [1], [0]) == 7
    assert stdlib_only()
    print("greedy_31 OK")


if __name__ == "__main__":
    main()
