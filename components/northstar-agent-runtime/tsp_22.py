"""k-TSP / m-TSP: split one tour into k routes minimizing the max route length (TSP-022), Simulated."""
from __future__ import annotations
import ast
import math

VERSION = "tsp-k-tsp.v1"


def split_tour(tour, dist, k):
    """Split ordered `tour` into k contiguous routes minimizing the maximum
    route path length. Returns (segments, max_length). Mock k-TSP."""
    n = len(tour)
    if n == 0:
        return ([], 0.0)
    k = max(1, min(k, n))
    # seg[i][j] = path length along tour from index i to j (i <= j)
    seg = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            seg[i][j] = seg[i][j - 1] + dist[tour[j - 1]][tour[j]]
    INF = math.inf
    dp = [[INF] * (k + 1) for _ in range(n + 1)]
    par = [[None] * (k + 1) for _ in range(n + 1)]
    dp[0][0] = 0.0
    for j in range(1, k + 1):
        for i in range(1, n + 1):
            for p in range(j - 1, i):
                prev = dp[p][j - 1]
                cur = seg[p][i - 1] if i - 1 >= p else 0.0
                cand = max(prev, cur)
                if cand < dp[i][j]:
                    dp[i][j] = cand
                    par[i][j] = p
    bounds = []
    i, j = n, k
    while j > 0:
        p = par[i][j]
        bounds.append((p, i))
        i, j = p, j - 1
    bounds.reverse()
    segments = [tour[a:b] for a, b in bounds]
    return (segments, dp[n][k])


def main() -> None:
    # points on a line: dist[i][j] = |i - j|
    n = 5
    dist = [[abs(i - j) for j in range(n)] for i in range(n)]
    tour = [0, 1, 2, 3, 4]
    segments, m = split_tour(tour, dist, 2)
    # small instance: optimal split of a unit line into 2 routes has max 2.0
    assert m == 2.0
    assert [c for s in segments for c in s] == tour
    # degenerate cases
    assert split_tour([], dist, 2) == ([], 0.0)
    segs1, m1 = split_tour(tour, dist, 99)
    assert len(segs1) == 5 and m1 == 0.0
    # correctness property: returned max equals recomputed max segment length
    def seg_len(s):
        return sum(dist[s[i]][s[i + 1]] for i in range(len(s) - 1))
    assert max(seg_len(s) for s in segments) == m
    assert stdlib_only()
    print('tsp-k-tsp.v1 OK')


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses", "random"}
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
