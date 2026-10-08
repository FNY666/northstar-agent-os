"""Prim/Dijkstra duality (mode flag) (MST-020), Real."""
from __future__ import annotations
import ast
import heapq
VERSION = "mst-20.v1"

def grow(n, edges, mode="prim", start=0):
    # One code path, two algorithms: Prim grows by minimum edge weight to
    # the tree, Dijkstra by minimum distance from the start. The only
    # difference is the relaxation rule.
    assert mode in ("prim", "dijkstra")
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        if u == v:
            continue
        adj[u].append((v, w))
        adj[v].append((u, w))
    INF = float("inf")
    dist = [INF] * n
    done = [False] * n
    par = [-1] * n
    dist[start] = 0
    heap = [(0, start)]
    tree = []
    while heap:
        d, u = heapq.heappop(heap)
        if done[u] or d > dist[u]:
            continue
        done[u] = True
        if par[u] != -1:
            ew = d if mode == "prim" else d - dist[par[u]]
            tree.append((par[u], u, ew))
        for v, w in adj[u]:
            nd = w if mode == "prim" else d + w
            if not done[v] and nd < dist[v]:
                dist[v] = nd
                par[v] = u
                heapq.heappush(heap, (nd, v))
    return dist, tree

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools"}
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
    e = [(0, 1, 1), (1, 2, 2), (0, 2, 3)]
    _, tree = grow(3, e, mode="prim")
    assert sum(w for _, _, w in tree) == 3
    dist, _ = grow(3, e, mode="dijkstra", start=0)
    assert dist == [0, 1, 3], dist
    dist, _ = grow(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1)], mode="dijkstra", start=0)
    assert dist == [0, 1, 2, 3]
    assert stdlib_only()
    print("mst-20 OK")


if __name__ == "__main__":
    main()
