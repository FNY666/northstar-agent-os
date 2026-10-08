"""Topological sort variant: Kahn taking an edge list (T-10)."""
from __future__ import annotations
import ast

VERSION = "topo_10.v1"

def topo_sort_edges(edges):
    graph = {}
    for u, v in edges:
        graph.setdefault(u, []).append(v)
        graph.setdefault(v, [])
    indeg = {u: 0 for u in graph}
    for u, v in edges:
        indeg[v] += 1
    queue = [u for u, d in indeg.items() if d == 0]
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in graph[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
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
    o = topo_sort_edges([("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")])
    assert o[0] == "a" and o[-1] == "d" and set(o) == {"a", "b", "c", "d"}
    assert topo_sort_edges([(1, 2), (2, 3)]) == [1, 2, 3]
    assert topo_sort_edges([("a", "b"), ("b", "a")]) is None
    assert topo_sort_edges([]) == []
    assert stdlib_only()
    print("topo_10 OK")


if __name__ == "__main__":
    main()
