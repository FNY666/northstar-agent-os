"""Bellman-Ford with negative cycle detection (SP-012), Real."""
from __future__ import annotations
import ast

VERSION = "sp-12.v1"

INF = float("inf")

def bellman_ford_nc(n, edges, src):
    dist = [INF] * n
    dist[src] = 0
    for _ in range(n - 1):
        for u, v, w in edges:
            if dist[u] != INF and dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
    for u, v, w in edges:
        if dist[u] != INF and dist[u] + w < dist[v]:
            return None, True
    return dist, False

def main() -> None:
    cyc = [(0, 1, 1), (1, 2, -1), (2, 0, -1)]
    d, neg = bellman_ford_nc(3, cyc, 0)
    assert neg is True and d is None
    ok = [(0, 1, 4), (0, 2, 1), (1, 2, 2), (2, 3, 1)]
    d, neg = bellman_ford_nc(4, ok, 0)
    assert neg is False and d == [0, 4, 1, 2]
    disc = [(0, 1, 1), (2, 3, -5), (3, 2, -5)]
    d, neg = bellman_ford_nc(4, disc, 0)
    assert neg is False
    d, neg = bellman_ford_nc(1, [], 0)
    assert neg is False and d == [0]
    assert stdlib_only()
    print("sp-12 OK")

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
