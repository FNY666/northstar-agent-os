"""Topological sort variant: Kahn picking max node, lexicographically largest order (T-04)."""
from __future__ import annotations
import ast

VERSION = "topo_04.v1"

def topo_sort(graph):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    zero = [u for u, d in indeg.items() if d == 0]
    order = []
    while zero:
        u = max(zero)
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
    g = {"b": ["d"], "a": ["d"], "c": [], "d": []}
    o = topo_sort(g)
    assert o == ["c", "b", "a", "d"]
    assert topo_sort({"b": ["a"], "a": []}) == ["b", "a"]
    assert topo_sort({"a": ["b"], "b": ["a"]}) is None
    assert stdlib_only()
    print("topo_04 OK")


if __name__ == "__main__":
    main()
