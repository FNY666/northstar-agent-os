"""Topological sort variant: critical path with task durations (T-37)."""
from __future__ import annotations
import ast

VERSION = "topo_37.v1"

def critical_path(graph, duration):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    queue = [u for u, d in indeg.items() if d == 0]
    order = []
    est = {u: 0 for u in indeg}
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in graph.get(u, []):
            cand = est[u] + duration.get(u, 0)
            if cand > est[v]:
                est[v] = cand
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    if len(order) != len(indeg):
        return None, {}
    finish = {u: est[u] + duration.get(u, 0) for u in indeg}
    return order, finish

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
    o, f = critical_path({1: [2], 2: [3], 3: []}, {1: 2, 2: 3, 3: 1})
    assert o == [1, 2, 3] and f == {1: 2, 2: 5, 3: 6}
    o2, f2 = critical_path({"a": ["b"], "b": ["a"]}, {})
    assert o2 is None and f2 == {}
    o3, f3 = critical_path({"a": []}, {"a": 4})
    assert f3 == {"a": 4}
    assert stdlib_only()
    print("topo_37 OK")


if __name__ == "__main__":
    main()
