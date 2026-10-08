"""Asymmetric TSP via Held-Karp bitmask DP (TSP-020), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-asymmetric.v1"


def asymmetric_held_karp(dist: list[list[float]]) -> tuple[list[int], float]:
    """Held-Karp DP for the asymmetric TSP on a directed distance matrix.
    Returns (best tour, best length). Tour starts at city 0."""
    n = len(dist)
    if n == 0:
        return [], 0.0
    if n == 1:
        return [0], 0.0
    INF = float("inf")
    dp = [[INF] * n for _ in range(1 << n)]
    parent = [[-1] * n for _ in range(1 << n)]
    dp[1][0] = 0.0
    for mask in range(1 << n):
        for u in range(n):
            if dp[mask][u] == INF:
                continue
            for v in range(n):
                if mask & (1 << v):
                    continue
                nmask = mask | (1 << v)
                cand = dp[mask][u] + dist[u][v]
                if cand < dp[nmask][v]:
                    dp[nmask][v] = cand
                    parent[nmask][v] = u
    full = (1 << n) - 1
    best_len = INF
    last = -1
    for u in range(1, n):
        cand = dp[full][u] + dist[u][0]
        if cand < best_len:
            best_len, last = cand, u
    tour = [last]
    mask = full
    while last != 0:
        prev = parent[mask][last]
        tour.append(prev)
        mask ^= 1 << last
        last = prev
    tour.reverse()
    return tour, best_len


def tour_length(dist: list[list[float]], tour: list[int]) -> float:
    n = len(tour)
    if n == 0:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))


def main() -> None:
    dist = [
        [0, 10, 15],
        [5, 0, 9],
        [6, 13, 0],
    ]
    tour, length = asymmetric_held_karp(dist)
    assert sorted(tour) == [0, 1, 2], "valid tour must visit each city exactly once"
    assert length == 25.0, f"expected asymmetric optimum 25, got {length}"
    assert asymmetric_held_karp([]) == ([], 0.0)
    assert asymmetric_held_karp([[0]]) == ([0], 0.0)
    assert length == sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))
    assert tour[0] == 0, "tour must start at city 0"
    assert tour_length(dist, tour) == length
    sym = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    t4, l4 = asymmetric_held_karp(sym)
    assert l4 == 80.0, f"Held-Karp on symmetric 4x4 must be 80, got {l4}"
    assert stdlib_only()
    print("tsp-asymmetric.v1 OK")


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
