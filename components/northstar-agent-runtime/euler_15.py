"""Eulerian existence check undirected (EULER-015), Real."""
from __future__ import annotations
import ast

VERSION = "euler-15.v1"

def has_eulerian(edges):
    """True iff undirected edge list has Eulerian circuit or trail."""
    if not edges:
        return True
    deg = {}
    adj = {}
    for u, v in edges:
        deg[u] = deg.get(u, 0) + 1
        deg[v] = deg.get(v, 0) + 1
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)
    if sum(d % 2 for d in deg.values()) not in (0, 2):
        return False
    start = next(iter(adj))
    seen = {start}
    stack = [start]
    while stack:
        u = stack.pop()
        for v in adj[u]:
            if v not in seen:
                seen.add(v)
                stack.append(v)
    return all(u in seen for u in deg)

def main() -> None:
    assert has_eulerian([(0, 1), (1, 2), (2, 0)])
    assert has_eulerian([(0, 1), (1, 2), (2, 3)])
    assert not has_eulerian([(0, 1), (0, 2), (0, 3)])
    assert not has_eulerian([(0, 1), (1, 0), (2, 3), (3, 2)])
    assert has_eulerian([])
    assert has_eulerian([(0, 0)])
    assert stdlib_only()
    print("euler-15.v1 OK")

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


if __name__ == "__main__":
    main()
