"""Topological sort variant: Kahn with stable tie-break by node order (T-14)."""
from __future__ import annotations
import ast

VERSION = "topo_14.v1"

def topo_sort(graph, node_order=None):
    indeg = {}
    seen = []
    def touch(u):
        if u not in indeg:
            indeg[u] = 0
            seen.append(u)
    for u in graph:
        touch(u)
        for v in graph[u]:
            touch(v)
            indeg[v] += 1
    if node_order:
        rank = {u: i for i, u in enumerate(node_order)}
    else:
        rank = {u: i for i, u in enumerate(seen)}
    queue = sorted([u for u, d in indeg.items() if d == 0], key=lambda u: rank.get(u, 10 ** 9))
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
        queue.sort(key=lambda u: rank.get(u, 10 ** 9))
    return order if len(order) == len(indeg) else None

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    g = {"b": ["d"], "a": ["d"], "c": [], "d": []}
    assert topo_sort(g, ["c", "b", "a", "d"])[:3] == ["c", "b", "a"]
    assert topo_sort(g)[0] == "b"
    assert topo_sort({"a": ["b"], "b": ["a"]}) is None
    assert stdlib_only()
    print("topo_14 OK")


if __name__ == "__main__":
    main()
