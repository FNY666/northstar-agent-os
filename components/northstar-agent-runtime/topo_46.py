"""Topological sort variant: DFS with discovery and finish timestamps (T-46)."""
from __future__ import annotations
import ast

VERSION = "topo_46.v1"

def topo_sort(graph):
    visited = set()
    on_path = set()
    order = []
    disc = {}
    fin = {}
    tick = [0]
    bad = []
    def visit(u):
        if bad or u in visited:
            return
        if u in on_path:
            bad.append(True)
            return
        on_path.add(u)
        tick[0] += 1
        disc[u] = tick[0]
        for v in graph.get(u, []):
            visit(v)
        on_path.discard(u)
        visited.add(u)
        tick[0] += 1
        fin[u] = tick[0]
        order.append(u)
    for u in graph:
        visit(u)
    if bad:
        return None, {}, {}
    return order[::-1], disc, fin

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
    o, d, f = topo_sort({1: [2], 2: [3], 3: []})
    assert o == [1, 2, 3]
    assert all(d[u] < f[u] for u in d)
    assert d[1] < d[2] < d[3] and f[3] < f[2] < f[1]
    assert topo_sort({"a": ["b"], "b": ["a"]}) == (None, {}, {})
    assert stdlib_only()
    print("topo_46 OK")


if __name__ == "__main__":
    main()
