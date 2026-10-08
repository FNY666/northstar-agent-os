"""Shortest path with exactly K edges (SP-039), Real."""
from __future__ import annotations
import ast

VERSION = "sp-39.v1"

INF = float("inf")

def k_edge_path(n, edges, src, dst, k):
    dist = [INF] * n
    dist[src] = 0
    for _ in range(k):
        nd = [INF] * n
        for u, v, w in edges:
            if dist[u] != INF and dist[u] + w < nd[v]:
                nd[v] = dist[u] + w
        dist = nd
    return dist[dst]

def main() -> None:
    edges = [(0, 1, 1), (1, 2, 1), (0, 2, 5)]
    assert k_edge_path(3, edges, 0, 2, 1) == 5
    assert k_edge_path(3, edges, 0, 2, 2) == 2
    assert k_edge_path(3, edges, 0, 2, 3) == INF
    assert k_edge_path(3, edges, 0, 0, 0) == 0
    assert stdlib_only()
    print("sp-39 OK")

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
