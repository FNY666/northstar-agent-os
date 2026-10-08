"""intv_19: Smallest interval containing each query (min_interval_query).

Sort intervals by size, sweep queries in order with a min-heap on end.

Time complexity: O((n + q) log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

import heapq
INTV_19 = "intv-19.v1"


def min_interval_query(intervals, queries):
    """For each query, size of the smallest interval containing it (-1 if none)."""
    ivs = sorted(intervals, key=lambda x: x[0])
    order = sorted(range(len(queries)), key=lambda i: queries[i])
    heap = []
    ans = [-1] * len(queries)
    k = 0
    for qi in order:
        q = queries[qi]
        while k < len(ivs) and ivs[k][0] <= q:
            s, e = ivs[k]
            heapq.heappush(heap, (e - s + 1, e))
            k += 1
        while heap and heap[0][1] < q:
            heapq.heappop(heap)
        if heap:
            ans[qi] = heap[0][0]
    return ans

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
    assert min_interval_query([(1, 4), (2, 4), (3, 6), (4, 4)], [2, 3, 4, 5]) == [3, 3, 1, 4]
    assert min_interval_query([(2, 3), (2, 5), (1, 8), (20, 25)], [2, 19, 5, 22]) == [2, -1, 4, 6]
    assert min_interval_query([], [1]) == [-1]
    assert min_interval_query([(1, 1)], [1]) == [1]
    assert min_interval_query([(1, 5)], [6]) == [-1]
    assert stdlib_only()
    print("intv_19 OK")


if __name__ == "__main__":
    main()
