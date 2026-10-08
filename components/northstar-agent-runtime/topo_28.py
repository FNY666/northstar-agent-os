"""Topological sort variant: DFS reporting weakly connected components (T-28)."""
from __future__ import annotations
import ast

VERSION = "topo_28.v1"

def topo_sort_components(graph):
    nodes = list(graph)
    for u in graph:
        for v in graph[u]:
            if v not in graph and v not in nodes:
                nodes.append(v)
    visited = set()
    on_path = set()
    order = []
    comps = []
    bad = []
    def visit(u, comp):
        if bad:
            return
        if u in on_path:
            bad.append(True)
            return
        if u in visited:
            return
        on_path.add(u)
        visited.add(u)
        comp.append(u)
        for v in graph.get(u, []):
            visit(v, comp)
        on_path.discard(u)
        order.append(u)
    for s in nodes:
        if s not in visited:
            comp = []
            visit(s, comp)
            if comp:
                comps.append(sorted(comp))
    if bad:
        return None, []
    return order[::-1], comps

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
    o, cs = topo_sort_components({1: [2], 2: [], 3: [4], 4: []})
    assert len(cs) == 2 and o is not None
    o2, cs2 = topo_sort_components({1: [2], 2: [3], 3: []})
    assert len(cs2) == 1
    assert topo_sort_components({1: [2], 2: [1]}) == (None, [])
    assert o.index(1) < o.index(2)
    assert stdlib_only()
    print("topo_28 OK")


if __name__ == "__main__":
    main()
