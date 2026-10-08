"""Topological sort variant: order of the reversed graph (T-23)."""
from __future__ import annotations
import ast

VERSION = "topo_23.v1"

def _kahn(graph):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    queue = [u for u, d in indeg.items() if d == 0]
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    return order if len(order) == len(indeg) else None

def reverse_topo(graph):
    rev = {}
    for u in graph:
        rev.setdefault(u, [])
        for v in graph[u]:
            rev.setdefault(v, []).append(u)
    return _kahn(rev)

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
    assert reverse_topo({1: [2], 2: [3], 3: []}) == [3, 2, 1]
    o = reverse_topo({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []})
    assert o[0] == "d" and o[-1] == "a"
    assert reverse_topo({"a": ["b"], "b": ["a"]}) is None
    assert stdlib_only()
    print("topo_23 OK")


if __name__ == "__main__":
    main()
