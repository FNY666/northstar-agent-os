"""Prize-collecting TSP: shortest tour from depot collecting at least a prize target (TSP-023), Simulated."""
from __future__ import annotations
import ast
import itertools
import math

VERSION = "tsp-prize-collecting.v1"


def prize_collecting_tsp(dist, prizes, prize_target, start=0):
    """DP over subsets: shortest tour starting/ending at `start` whose
    visited vertices collect total prize >= prize_target.
    Returns (path, length, prize); (None, inf, 0) if infeasible."""
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
    best, bestkey = INF, None
    for mask in range(1 << n):
        if not (mask >> start) & 1:
            continue
        if sum(prizes[i] for i in range(n) if (mask >> i) & 1) < prize_target:
            continue
        for u in range(n):
            if not (mask >> u) & 1:
                continue
            tot = dp[mask][u] + dist[u][start]
            if tot < best:
                best, bestkey = tot, (mask, u)
    if bestkey is None:
        return (None, math.inf, 0)
    mask, u = bestkey
    path = [u]
    while (mask, u) in parent:
        mask, u = parent[(mask, u)]
        path.append(u)
    path.reverse()
    path.append(start)
    prize = sum(prizes[i] for i in path[:-1])
    return (path, best, prize)


def main() -> None:
    n = 4
    dist = [[abs(i - j) for j in range(n)] for i in range(n)]
    prizes = [0, 10, 1, 10]
    path, length, prize = prize_collecting_tsp(dist, prizes, 15)
    # small instance: visit 1 and 3 (or 1,2,3); shortest feasible tour is 6.0
    assert length == 6.0
    assert prize >= 15
    # degenerate case: empty input
    assert prize_collecting_tsp([], [], 5) == ([], 0.0, 0)
    # correctness property: optimum equals brute force over subsets + perms
    best = math.inf
    for r in range(1, n + 1):
        for subset in itertools.combinations(range(1, n), r):
            if sum(prizes[i] for i in subset) < 15:
                continue
            for perm in itertools.permutations(subset):
                t = [0] + list(perm) + [0]
                L = sum(dist[t[i]][t[i + 1]] for i in range(len(t) - 1))
                best = min(best, L)
    assert length == best
    assert path[0] == 0 and path[-1] == 0
    assert stdlib_only()
    print('tsp-prize-collecting.v1 OK')


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
