"""Steiner tree metric-closure 2-approximation (MST-041), Simulated."""
from __future__ import annotations
import ast

VERSION = "mst-41.v1"

def steiner_approx(n, edges, terminals):
    # 2-approximation for Steiner tree: all-pairs shortest paths, MST over
    # terminals in the metric closure. Documented approximation.
    INF = float("inf")
    dist = [[INF] * n for _ in range(n)]
    for i in range(n):
        dist[i][i] = 0
    for u, v, w in edges:
        if w < dist[u][v]:
            dist[u][v] = dist[v][u] = w
    for k in range(n):
        for i in range(n):
            dik = dist[i][k]
            for j in range(n):
                if dik + dist[k][j] < dist[i][j]:
                    dist[i][j] = dik + dist[k][j]
    t = list(terminals)
    m = len(t)
    if m <= 1:
        return 0
    medges = []
    for i in range(m):
        for j in range(i + 1, m):
            medges.append((i, j, dist[t[i]][t[j]]))
    parent = list(range(m))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    total = 0
    for i, j, w in sorted(medges, key=lambda e: e[2]):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri
            total += w
    return total

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
    e = [(0, 1, 1), (1, 2, 1), (0, 2, 10)]
    assert steiner_approx(3, e, [0, 2]) == 2
    assert steiner_approx(3, e, [0, 1, 2]) == 2
    assert steiner_approx(3, e, [1]) == 0
    e2 = [(0, 3, 1), (1, 3, 1), (2, 3, 1), (0, 1, 10)]
    assert steiner_approx(4, e2, [0, 1, 2]) == 4
    assert stdlib_only()
    print("mst-41 OK")


if __name__ == "__main__":
    main()
