"""graph_46: Traveling salesman via Held-Karp DP (exact, small n). Stdlib only.

GRAPH_46_VERSION = graph-46.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Tuple

GRAPH_46_VERSION = "graph-46.v1"


def held_karp_tsp(dist: List[List[float]]) -> Tuple[float, List[int]]:
    """Exact TSP tour cost and route. dist: n x n matrix. O(n^2 2^n)."""
    n = len(dist)
    if n == 0:
        return 0.0, []
    if n == 1:
        return 0.0, [0]
    INF = float("inf")
    # dp[mask][j] = min cost to reach j visiting mask (mask includes 0 and j)
    dp = [[INF] * n for _ in range(1 << n)]
    parent = [[-1] * n for _ in range(1 << n)]
    dp[1][0] = 0.0
    for mask in range(1 << n):
        if not (mask & 1):
            continue
        for j in range(n):
            if not (mask & (1 << j)) or dp[mask][j] == INF:
                continue
            for k in range(n):
                if mask & (1 << k):
                    continue
                nmask = mask | (1 << k)
                nd = dp[mask][j] + dist[j][k]
                if nd < dp[nmask][k]:
                    dp[nmask][k] = nd
                    parent[nmask][k] = j
    full = (1 << n) - 1
    best = INF
    last = -1
    for j in range(1, n):
        c = dp[full][j] + dist[j][0]
        if c < best:
            best = c
            last = j
    # reconstruct
    route = [0]
    mask, j = full, last
    rev = []
    while j != 0:
        rev.append(j)
        pj = parent[mask][j]
        mask ^= 1 << j
        j = pj
    route += rev[::-1] + [0]
    return best, route


def test_tsp_square():
    d = [[0, 1, 2, 1], [1, 0, 1, 2], [2, 1, 0, 1], [1, 2, 1, 0]]
    cost, route = held_karp_tsp(d)
    assert cost == 4.0
    assert route[0] == route[-1] == 0 and sorted(route[:-1]) == [0, 1, 2, 3]


def test_tsp_triangle():
    d = [[0, 10, 15], [10, 0, 20], [15, 20, 0]]
    cost, route = held_karp_tsp(d)
    assert cost == 45.0 and len(route) == 4


def test_tsp_asymmetric():
    d = [[0, 1, 5], [5, 0, 1], [1, 5, 0]]
    cost, _ = held_karp_tsp(d)
    assert cost == 3.0


def test_tsp_single():
    assert held_karp_tsp([[0]]) == (0.0, [0])


def test_tsp_empty():
    assert held_karp_tsp([]) == (0.0, [])


def main() -> None:
    test_tsp_square()
    test_tsp_triangle()
    test_tsp_asymmetric()
    test_tsp_single()
    test_tsp_empty()
    print("graph_46 (TSP Held-Karp) OK")


if __name__ == "__main__":
    main()
