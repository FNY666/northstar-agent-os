"""Topological sort variant: returning nodes involved in cycles (T-38)."""
from __future__ import annotations
import ast

VERSION = "topo_38.v1"

def cycle_nodes(graph):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    queue = [u for u, d in indeg.items() if d == 0]
    removed = set()
    while queue:
        u = queue.pop(0)
        removed.add(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    return set(indeg) - removed

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
    assert cycle_nodes({"a": ["b"], "b": ["a"], "c": ["a"]}) == {"a", "b"}
    assert cycle_nodes({"a": ["b"], "b": ["c"], "c": []}) == set()
    assert cycle_nodes({"x": ["x"]}) == {"x"}
    assert stdlib_only()
    print("topo_38 OK")


if __name__ == "__main__":
    main()
