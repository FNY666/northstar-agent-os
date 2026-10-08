"""Topological sort variant: Kahn returning BFS levels (T-07)."""
from __future__ import annotations
import ast

VERSION = "topo_07.v1"

def topo_levels(graph):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    cur = [u for u, d in indeg.items() if d == 0]
    levels = []
    seen = 0
    while cur:
        levels.append(sorted(cur))
        seen += len(cur)
        nxt = []
        for u in cur:
            for v in graph.get(u, []):
                indeg[v] -= 1
                if indeg[v] == 0:
                    nxt.append(v)
        cur = nxt
    if seen != len(indeg):
        return None
    return levels

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
    assert topo_levels({"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}) == [["a"], ["b", "c"], ["d"]]
    assert topo_levels({1: [2], 2: [3], 3: []}) == [[1], [2], [3]]
    assert topo_levels({"a": ["b"], "b": ["a"]}) is None
    assert topo_levels({}) == []
    assert stdlib_only()
    print("topo_07 OK")


if __name__ == "__main__":
    main()
