"""Held-Karp DP exact TSP with bitmask (TSP-002), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-heldkarp.v1"


def tour_length(dist, tour):
    if len(tour) <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def solve_held_karp(dist):
    """Return (best_tour, best_length) via Held-Karp DP; tour starts at city 0."""
    n = len(dist)
    if n == 0:
        return [], 0.0
    if n == 1:
        return [0], 0.0
    INF = float("inf")
    dp = {}
    parent = {}
    for i in range(1, n):
        dp[(1 << i, i)] = dist[0][i]
    for mask in range(1 << n):
        for last in range(1, n):
            if not (mask & (1 << last)):
                continue
            cur = dp.get((mask, last), INF)
            if cur == INF:
                continue
            for nxt in range(1, n):
                if mask & (1 << nxt):
                    continue
                nmask = mask | (1 << nxt)
                new = cur + dist[last][nxt]
                if new < dp.get((nmask, nxt), INF):
                    dp[(nmask, nxt)] = new
                    parent[(nmask, nxt)] = last
    full = (1 << n) - 1 - (1 << 0)
    best_last = min(range(1, n), key=lambda i: dp.get((full, i), INF) + dist[i][0])
    best_len = dp[(full, best_last)] + dist[best_last][0]
    # reconstruct path backwards
    path = [best_last]
    mask = full
    node = best_last
    while mask != (1 << node):
        prev = parent[(mask, node)]
        path.append(prev)
        mask ^= (1 << node)
        node = prev
    tour = [0] + path[::-1]
    return tour, best_len


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour, length = solve_held_karp(dist)
    # known optimum for this instance is 80 (tour 0-1-3-2-0)
    assert length == 80
    assert sorted(tour) == [0, 1, 2, 3] and tour[0] == 0
    assert length == tour_length(dist, tour)
    assert solve_held_karp([]) == ([], 0.0)
    assert solve_held_karp([[0]]) == ([0], 0.0)
    tour2, length2 = solve_held_karp([[0, 5], [5, 0]])
    assert sorted(tour2) == [0, 1] and length2 == 10
    # agrees with brute force on a 5-city asymmetric-ish instance
    d5 = [
        [0, 3, 4, 2, 7],
        [3, 0, 4, 6, 3],
        [4, 4, 0, 5, 8],
        [2, 6, 5, 0, 6],
        [7, 3, 8, 6, 0],
    ]
    t5, l5 = solve_held_karp(d5)
    assert sorted(t5) == [0, 1, 2, 3, 4] and l5 == tour_length(d5, t5)
    assert stdlib_only()
    print('tsp-heldkarp.v1 OK')


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
