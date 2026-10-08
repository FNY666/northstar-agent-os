"""Minimum-diameter spanning tree center heuristic (MST-046), Simulated."""
from __future__ import annotations
import ast
import heapq
VERSION = "mst-46.v1"

def min_diameter_heuristic(n, edges):
    # Heuristic: shortest-path tree rooted at the graph center.
    # Documented approximation; the exact minimum-diameter spanning tree
    # needs more machinery.
    INF = float("inf")
    dist = [[INF] * n for _ in range(n)]
    for i in range(n):
        dist[i][i] = 0
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        if u == v:
            continue
        if w < dist[u][v]:
            dist[u][v] = dist[v][u] = w
        adj[u].append((v, w))
        adj[v].append((u, w))
    for k in range(n):
        for i in range(n):
            dik = dist[i][k]
            for j in range(n):
                if dik + dist[k][j] < dist[i][j]:
                    dist[i][j] = dik + dist[k][j]
    ecc = [max(dist[i]) for i in range(n)]
    center = min(range(n), key=lambda i: ecc[i])
    dd = [INF] * n
    par = [-1] * n
    dd[center] = 0
    heap = [(0, center)]
    done = [False] * n
    while heap:
        d, u = heapq.heappop(heap)
        if done[u]:
            continue
        done[u] = True
        for v, w in adj[u]:
            if dd[u] + w < dd[v]:
                dd[v] = dd[u] + w
                par[v] = u
                heapq.heappush(heap, (dd[v], v))
    tree = [(par[v], v, dd[v] - dd[par[v]]) for v in range(n) if v != center and par[v] != -1]
    return ecc[center], tree

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
    ecc, tree = min_diameter_heuristic(3, [(0, 1, 1), (1, 2, 1), (0, 2, 10)])
    assert ecc == 1 and len(tree) == 2
    ecc, tree = min_diameter_heuristic(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1)])
    assert ecc == 2
    assert stdlib_only()
    print("mst-46 OK")


if __name__ == "__main__":
    main()
