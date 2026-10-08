"""Topological sort variant: Kahn layers by longest path (T-24)."""
from __future__ import annotations
import ast

VERSION = "topo_24.v1"

def topo_layers_longest(graph):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    queue = [u for u, d in indeg.items() if d == 0]
    level = {u: 0 for u in queue}
    order = []
    while queue:
        u = queue.pop(0)
        order.append(u)
        for v in graph.get(u, []):
            if level.get(v, -1) < level[u] + 1:
                level[v] = level[u] + 1
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    if len(order) != len(indeg):
        return None
    layers = {}
    for u, l in level.items():
        layers.setdefault(l, []).append(u)
    return [sorted(layers[i]) for i in sorted(layers)]

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
    assert topo_layers_longest({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}) == [["a"], ["b", "c"], ["d"]]
    g = {"a": ["b"], "b": ["c"], "a2": ["c"], "c": []}
    ls = topo_layers_longest(g)
    assert ls[0] == ["a", "a2"] and ls[-1] == ["c"]
    assert topo_layers_longest({"a": ["a"]}) is None
    assert stdlib_only()
    print("topo_24 OK")


if __name__ == "__main__":
    main()
