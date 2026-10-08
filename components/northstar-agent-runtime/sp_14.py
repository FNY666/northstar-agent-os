"""Bellman-Ford with path reconstruction (SP-014), Real."""
from __future__ import annotations
import ast

VERSION = "sp-14.v1"

INF = float("inf")

def bellman_ford_path(n, edges, src, dst):
    dist = [INF] * n
    parent = [-1] * n
    dist[src] = 0
    for _ in range(n - 1):
        for u, v, w in edges:
            if dist[u] != INF and dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                parent[v] = u
    if dist[dst] == INF:
        return INF, []
    path = []
    cur = dst
    seen = set()
    while cur != -1 and cur not in seen:
        seen.add(cur)
        path.append(cur)
        cur = parent[cur]
    path.reverse()
    return dist[dst], path

def main() -> None:
    edges = [(0, 1, 4), (0, 2, 1), (1, 2, 2), (2, 3, 1), (1, 3, 5)]
    d, p = bellman_ford_path(4, edges, 0, 3)
    assert d == 2 and p == [0, 2, 3]
    neg = [(0, 1, 1), (1, 2, -2), (0, 2, 4)]
    d, p = bellman_ford_path(3, neg, 0, 2)
    assert d == -1 and p == [0, 1, 2]
    d, p = bellman_ford_path(3, [(0, 1, 1)], 0, 2)
    assert d == INF and p == []
    d, p = bellman_ford_path(3, [(0, 1, 1)], 1, 1)
    assert d == 0 and p == [1]
    assert stdlib_only()
    print("sp-14 OK")

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
