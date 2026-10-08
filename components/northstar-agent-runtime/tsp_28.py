"""Bitonic traveling salesman, exact O(n^2) dynamic programming (TSP-028), Simulated."""
from __future__ import annotations
import ast
import itertools
import math

VERSION = "tsp-bitonic.v1"


def _dist(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


def bitonic_tsp(points):
    """Exact bitonic TSP. Points are sorted by x internally.
    Returns (tour, length) with tour as indices into the original list."""
    n = len(points)
    if n == 0:
        return ([], 0.0)
    order = sorted(range(n), key=lambda i: (points[i][0], points[i][1]))
    pts = [points[i] for i in order]
    if n == 1:
        return ([order[0]], 0.0)
    d = [[_dist(pts[i], pts[j]) for j in range(n)] for i in range(n)]
    if n == 2:
        return ([order[0], order[1]], 2.0 * d[0][1])
    INF = math.inf
    dp = [[INF] * n for _ in range(n)]
    pred = [[None] * n for _ in range(n)]
    dp[1][0] = d[0][1]
    for i in range(2, n):
        for j in range(i - 1):
            dp[i][j] = dp[i - 1][j] + d[i - 1][i]
            pred[i][j] = (i - 1, j)
        best, bk = INF, None
        for k in range(i - 1):
            cand = dp[i - 1][k] + d[k][i]
            if cand < best:
                best, bk = cand, k
        dp[i][i - 1] = best
        pred[i][i - 1] = (i - 1, bk)
    best, bk = INF, None
    for k in range(n - 1):
        cand = dp[n - 1][k] + d[k][n - 1]
        if cand < best:
            best, bk = cand, k
    edges = [(bk, n - 1), (0, 1)]
    i, j = n - 1, bk
    while (i, j) != (1, 0):
        pi, pj = pred[i][j]
        edges.append((pj, i) if j == i - 1 else (pi, i))
        i, j = pi, pj
    adj = [[] for _ in range(n)]
    for a, b in edges:
        adj[a].append(b)
        adj[b].append(a)
    tour_sorted = [0]
    prev, cur = -1, 0
    for _ in range(n - 1):
        nxt = adj[cur][0] if adj[cur][0] != prev else adj[cur][1]
        tour_sorted.append(nxt)
        prev, cur = cur, nxt
    tour = [order[i] for i in tour_sorted]
    length = sum(_dist(points[tour[i]], points[tour[(i + 1) % n]]) for i in range(n))
    return (tour, length)


def _brute_bitonic(points):
    """Minimum over all bitonic tours by enumerating the upper chain."""
    n = len(points)
    pts = sorted(points, key=lambda p: (p[0], p[1]))
    best = math.inf
    for r in range(n - 1):
        for upper in itertools.combinations(range(1, n - 1), r):
            lower = [i for i in range(1, n - 1) if i not in upper]
            t = [0] + list(upper) + [n - 1] + lower[::-1] + [0]
            L = sum(_dist(pts[t[i]], pts[t[i + 1]]) for i in range(len(t) - 1))
            best = min(best, L)
    return best


def main() -> None:
    # small instance: points on a line -> optimal bitonic tour is 2 * span
    pts = [(0.0, 0.0), (1.0, 0.0), (2.0, 0.0), (3.0, 0.0)]
    tour, length = bitonic_tsp(pts)
    assert abs(length - 6.0) < 1e-9
    assert sorted(tour) == [0, 1, 2, 3]
    # degenerate cases
    assert bitonic_tsp([]) == ([], 0.0)
    assert bitonic_tsp([(5.0, 5.0)]) == ([0], 0.0)
    t2, l2 = bitonic_tsp([(0.0, 0.0), (3.0, 4.0)])
    assert abs(l2 - 10.0) < 1e-9 and sorted(t2) == [0, 1]
    # correctness property: DP optimum equals brute-force bitonic optimum
    pts5 = [(0.0, 0.0), (1.0, 2.0), (2.0, 1.0), (3.0, 3.0), (4.0, 0.0)]
    _, lb = bitonic_tsp(pts5)
    assert abs(lb - _brute_bitonic(pts5)) < 1e-9
    # and the returned tour really has that length
    tb, _ = bitonic_tsp(pts5)
    n5 = len(pts5)
    assert abs(sum(_dist(pts5[tb[i]], pts5[tb[(i + 1) % n5]]) for i in range(n5)) - lb) < 1e-9
    assert stdlib_only()
    print('tsp-bitonic.v1 OK')


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
