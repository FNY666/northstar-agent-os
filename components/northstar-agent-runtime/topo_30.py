"""Topological sort variant: boolean DAG validation (T-30)."""
from __future__ import annotations
import ast

VERSION = "topo_30.v1"

def is_dag(graph):
    indeg = {}
    for u in graph:
        indeg.setdefault(u, 0)
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    queue = [u for u, d in indeg.items() if d == 0]
    done = 0
    while queue:
        u = queue.pop()
        done += 1
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    return done == len(indeg)

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
    assert is_dag({"a": ["b"], "b": ["c"], "c": []}) is True
    assert is_dag({"a": ["b"], "b": ["a"]}) is False
    assert is_dag({"a": ["a"]}) is False
    assert is_dag({}) is True
    assert stdlib_only()
    print("topo_30 OK")


if __name__ == "__main__":
    main()
