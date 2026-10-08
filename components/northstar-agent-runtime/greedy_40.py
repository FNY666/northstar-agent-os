"""greedy_40: Prim minimum spanning tree (simplified).

Grow the tree by the cheapest edge crossing the cut, tracked with a min-heap.

Time complexity: O(E log V) time
Space complexity: O(V + E) auxiliary
"""

import ast
import sys
GREEDY_40_VERSION = "greedy-40.v1"


def prim_mst_weight(graph):
    """Return the MST weight of a connected undirected graph.

    graph: dict of node -> dict of neighbor -> weight.
    """
    import heapq
    nodes = list(graph)
    if not nodes:
        return 0
    in_mst = {nodes[0]}
    total = 0
    heap = [(w, nodes[0], v) for v, w in graph[nodes[0]].items()]
    heapq.heapify(heap)
    while heap and len(in_mst) < len(nodes):
        w, _u, v = heapq.heappop(heap)
        if v in in_mst:
            continue
        in_mst.add(v)
        total += w
        for to, wt in graph[v].items():
            if to not in in_mst:
                heapq.heappush(heap, (wt, v, to))
    return total

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
    g = {0: {1: 4, 7: 8}, 1: {0: 4, 2: 8, 7: 11}, 2: {1: 8, 3: 7, 5: 4, 8: 2}, 3: {2: 7, 4: 9, 5: 14}, 4: {3: 9, 5: 10}, 5: {2: 4, 3: 14, 4: 10, 6: 2}, 6: {5: 2, 7: 1, 8: 6}, 7: {0: 8, 1: 11, 6: 1, 8: 7}, 8: {2: 2, 6: 6, 7: 7}}
    assert prim_mst_weight(g) == 37
    assert prim_mst_weight({}) == 0
    assert prim_mst_weight({0: {}}) == 0
    assert prim_mst_weight({0: {1: 5}, 1: {0: 5}}) == 5
    assert stdlib_only()
    print("greedy_40 OK")


if __name__ == "__main__":
    main()
