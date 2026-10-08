"""greedy_39: Dijkstra shortest paths (simplified).

Greedily finalize the unvisited node with the smallest tentative distance.

Time complexity: O(V^2) time
Space complexity: O(V) auxiliary
"""

import ast
import sys
GREEDY_39_VERSION = "greedy-39.v1"


def dijkstra(graph, source):
    """Return {node: shortest distance} from source.

    graph: dict of node -> dict of neighbor -> non-negative weight.
    """
    import math
    dist = {node: math.inf for node in graph}
    dist[source] = 0
    unvisited = set(graph)
    while unvisited:
        u = min(unvisited, key=lambda n: dist[n])
        unvisited.discard(u)
        for v, w in graph[u].items():
            if dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
    return dist

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
    g = {"a": {"b": 4, "c": 2}, "b": {"c": 1, "d": 5}, "c": {"d": 8, "e": 10}, "d": {"e": 2}, "e": {}}
    assert dijkstra(g, "a") == {"a": 0, "b": 4, "c": 2, "d": 9, "e": 11}
    assert dijkstra({"s": {}}, "s") == {"s": 0}
    g2 = {"a": {"b": 1}, "b": {}, "c": {}}
    assert dijkstra(g2, "a")["c"] == float("inf")
    assert dijkstra({"a": {"b": 3}, "b": {"a": 3}}, "b") == {"a": 3, "b": 0}
    assert stdlib_only()
    print("greedy_39 OK")


if __name__ == "__main__":
    main()
