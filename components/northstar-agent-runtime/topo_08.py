"""Topological sort variant: Kahn detecting whether the order is unique (T-08)."""
from __future__ import annotations
import ast

VERSION = "topo_08.v1"

def topo_sort_unique(graph):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    queue = [u for u, d in indeg.items() if d == 0]
    order = []
    unique = True
    while queue:
        if len(queue) > 1:
            unique = False
        u = queue.pop(0)
        order.append(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    if len(order) != len(indeg):
        return None, False
    return order, unique

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
    o, u = topo_sort_unique({1: [2], 2: [3], 3: []})
    assert o == [1, 2, 3] and u is True
    o2, u2 = topo_sort_unique({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []})
    assert u2 is False and o2[0] == "a"
    assert topo_sort_unique({"a": ["b"], "b": ["a"]}) == (None, False)
    assert stdlib_only()
    print("topo_08 OK")


if __name__ == "__main__":
    main()
