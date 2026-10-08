"""Bellman-Ford with early convergence stop (SP-015), Real."""
from __future__ import annotations
import ast

VERSION = "sp-15.v1"

INF = float("inf")

def bellman_ford_early(n, edges, src):
    dist = [INF] * n
    dist[src] = 0
    iters = 0
    for i in range(n - 1):
        iters = i + 1
        updated = False
        for u, v, w in edges:
            if dist[u] != INF and dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                updated = True
        if not updated:
            break
    return dist, iters

def main() -> None:
    edges = [(0, 1, 1), (1, 2, 1)]
    d, it = bellman_ford_early(3, edges, 0)
    assert d == [0, 1, 2] and it <= 2
    d, it = bellman_ford_early(4, [(0, 1, 5)], 0)
    assert d == [0, 5, INF, INF] and it <= 2
    d, it = bellman_ford_early(1, [], 0)
    assert d == [0] and it == 0
    chain = [(i, i + 1, 1) for i in range(4)]
    d, it = bellman_ford_early(5, chain, 0)
    assert d == [0, 1, 2, 3, 4]
    assert stdlib_only()
    print("sp-15 OK")

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
