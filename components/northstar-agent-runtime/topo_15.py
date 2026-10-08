"""Topological sort variant: Kahn stopping after k nodes (T-15)."""
from __future__ import annotations
import ast

VERSION = "topo_15.v1"

def topo_first_k(graph, k):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    queue = [u for u, d in indeg.items() if d == 0]
    order = []
    while queue and len(order) < k:
        u = queue.pop(0)
        order.append(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    return order

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
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    assert topo_first_k(g, 0) == []
    assert topo_first_k(g, 1) == ["a"]
    assert len(topo_first_k(g, 2)) == 2 and topo_first_k(g, 2)[0] == "a"
    assert len(topo_first_k(g, 99)) == 4
    assert stdlib_only()
    print("topo_15 OK")


if __name__ == "__main__":
    main()
