"""Orienteering problem: maximize collected prize within a distance budget (TSP-024), Simulated."""
from __future__ import annotations
import ast
import itertools
import math

VERSION = "tsp-orienteering.v1"


def orienteering(dist, prizes, budget, start=0):
    """DP over subsets: among tours starting/ending at `start` with length
    <= budget, pick the one with maximum collected prize.
    Returns (path, length, prize)."""
    n = len(dist)
    if n == 0:
        return ([], 0.0, 0)
    INF = math.inf
    dp = [[INF] * n for _ in range(1 << n)]
    parent = {}
    dp[1 << start][start] = 0.0
    for mask in range(1 << n):
        for u in range(n):
            if not (mask >> u) & 1 or dp[mask][u] == INF:
                continue
            for v in range(n):
                if (mask >> v) & 1:
                    continue
                nm = mask | (1 << v)
                nd = dp[mask][u] + dist[u][v]
                if nd < dp[nm][v]:
                    dp[nm][v] = nd
                    parent[(nm, v)] = (mask, u)
    best_prize, best_len, bestkey = -1, 0.0, None
    for mask in range(1 << n):
        if not (mask >> start) & 1:
            continue
        pz = sum(prizes[i] for i in range(n) if (mask >> i) & 1)
        for u in range(n):
            if not (mask >> u) & 1:
                continue
            tot = dp[mask][u] + dist[u][start]
            if tot <= budget and (pz > best_prize or (pz == best_prize and tot < best_len)):
                best_prize, best_len, bestkey = pz, tot, (mask, u)
    mask, u = bestkey
    path = [u]
    while (mask, u) in parent:
        mask, u = parent[(mask, u)]
        path.append(u)
    path.reverse()
    path.append(start)
    return (path, best_len, best_prize)


def main() -> None:
    n = 4
    dist = [[abs(i - j) for j in range(n)] for i in range(n)]
    prizes = [0, 5, 5, 5]
    path, length, prize = orienteering(dist, prizes, 4.0)
    # small instance: budget 4.0 allows visiting {1,2} for prize 10
    assert prize == 10
    assert length <= 4.0
    # degenerate case: empty input
    assert orienteering([], [], 10.0) == ([], 0.0, 0)
    # degenerate case: budget too small to leave the depot
    p2, l2, z2 = orienteering(dist, prizes, 0.5)
    assert z2 == 0 and l2 <= 0.5 and p2[0] == 0 and p2[-1] == 0
    # correctness property: prize is optimal by brute force
    best = -1
    for r in range(n):
        for subset in itertools.combinations(range(1, n), r):
            for perm in itertools.permutations(subset):
                t = [0] + list(perm) + [0]
                L = sum(dist[t[i]][t[i + 1]] for i in range(len(t) - 1))
                if L <= 4.0:
                    best = max(best, sum(prizes[i] for i in subset))
    assert prize == best
    assert stdlib_only()
    print('tsp-orienteering.v1 OK')


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
