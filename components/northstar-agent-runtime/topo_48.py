"""Topological sort variant: Kahn returning node-to-level map (T-48)."""
from __future__ import annotations
import ast

VERSION = "topo_48.v1"

def topo_levels_map(graph):
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
    return level

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
    lv = topo_levels_map({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []})
    assert lv == {"a": 0, "b": 1, "c": 1, "d": 2}
    assert topo_levels_map({1: [2], 2: [3], 3: []}) == {1: 0, 2: 1, 3: 2}
    assert topo_levels_map({"a": ["a"]}) is None
    assert stdlib_only()
    print("topo_48 OK")


if __name__ == "__main__":
    main()
