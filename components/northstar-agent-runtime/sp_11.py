"""Bellman-Ford basic (SP-011), Real."""
from __future__ import annotations
import ast

VERSION = "sp-11.v1"

INF = float("inf")

def bellman_ford(n, edges, src):
    dist = [INF] * n
    dist[src] = 0
    for _ in range(n - 1):
        updated = False
        for u, v, w in edges:
            if dist[u] != INF and dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                updated = True
        if not updated:
            break
    return dist

def main() -> None:
    edges = [(0, 1, 4), (0, 2, 1), (1, 2, 2), (2, 3, 1), (1, 3, 5)]
    assert bellman_ford(4, edges, 0) == [0, 4, 1, 2]
    neg = [(0, 1, 1), (1, 2, -2), (0, 2, 4)]
    assert bellman_ford(3, neg, 0) == [0, 1, -1]
    assert bellman_ford(3, [(0, 1, 1)], 0) == [0, 1, INF]
    assert bellman_ford(1, [], 0) == [0]
    assert stdlib_only()
    print("sp-11 OK")

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
