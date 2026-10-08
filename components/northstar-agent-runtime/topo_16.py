"""Topological sort variant: DFS also returning finish times (T-16)."""
from __future__ import annotations
import ast

VERSION = "topo_16.v1"

def topo_sort(graph):
    visited = set()
    on_path = set()
    order = []
    finish = {}
    tick = [0]
    bad = []
    def visit(u):
        if bad or u in visited:
            return
        if u in on_path:
            bad.append(u)
            return
        on_path.add(u)
        for v in graph.get(u, []):
            visit(v)
        on_path.discard(u)
        visited.add(u)
        tick[0] += 1
        finish[u] = tick[0]
        order.append(u)
    for u in graph:
        visit(u)
    if bad:
        return None, {}
    return order[::-1], finish

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
    o, f = topo_sort({1: [2], 2: [3], 3: []})
    assert o == [1, 2, 3]
    assert f[3] < f[2] < f[1]
    o2, f2 = topo_sort({"a": ["b"], "b": ["a"]})
    assert o2 is None and f2 == {}
    assert set(f) == {1, 2, 3}
    assert stdlib_only()
    print("topo_16 OK")


if __name__ == "__main__":
    main()
