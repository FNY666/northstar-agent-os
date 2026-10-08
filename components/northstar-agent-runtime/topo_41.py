"""Topological sort variant: Kahn with weight tie-break (T-41)."""
from __future__ import annotations
import ast

VERSION = "topo_41.v1"

def topo_sort(graph, weight):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    zero = [u for u, d in indeg.items() if d == 0]
    order = []
    while zero:
        u = min(zero, key=lambda x: weight.get(x, 0))
        zero.remove(u)
        order.append(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                zero.append(v)
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
    g = {"a": ["c"], "b": ["c"], "c": []}
    assert topo_sort(g, {"a": 5, "b": 1, "c": 0})[0] == "b"
    assert topo_sort(g, {"a": 1, "b": 5, "c": 0})[0] == "a"
    assert topo_sort({"a": ["b"], "b": ["a"]}, {}) is None
    assert stdlib_only()
    print("topo_41 OK")


if __name__ == "__main__":
    main()
