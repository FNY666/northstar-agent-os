"""graph_47: Steiner tree via Dreyfus-Wagner DP (exact, few terminals). Stdlib only.

GRAPH_47_VERSION = graph-47.v1
"""
from __future__ import annotations

import heapq
from typing import Dict, Hashable, List, Tuple

GRAPH_47_VERSION = "graph-47.v1"


def _all_pairs(nodes: List[Hashable], edges: List[Tuple[Hashable, Hashable, float]]):
    INF = float("inf")
    dist = {u: {v: INF for v in nodes} for u in nodes}
    for u in nodes:
        dist[u][u] = 0.0
    for u, v, w in edges:
        if w < dist[u][v]:
            dist[u][v] = dist[v][u] = w
    for k in nodes:
        for i in nodes:
            dik = dist[i][k]
            if dik == INF:
                continue
            for j in nodes:
                nd = dik + dist[k][j]
                if nd < dist[i][j]:
                    dist[i][j] = nd
    return dist


def dreyfus_wagner(
    nodes: List[Hashable],
    edges: List[Tuple[Hashable, Hashable, float]],
    terminals: List[Hashable],
) -> float:
    """Minimum Steiner tree cost spanning terminals. O(3^k * n^2), k = #terminals."""
    k = len(terminals)
    if k <= 1:
        return 0.0
    INF = float("inf")
    dist = _all_pairs(nodes, edges)
    # dp[mask][v] = min cost of subtree spanning terminals in mask, ending at v
    dp = [[INF] * len(nodes) for _ in range(1 << k)]
    idx = {u: i for i, u in enumerate(nodes)}
    for i, t in enumerate(terminals):
        for v in nodes:
            dp[1 << i][idx[v]] = dist[t][v]
    for mask in range(1, 1 << k):
        # combine submasks
        sub = (mask - 1) & mask
        while sub:
            other = mask ^ sub
            if other and sub < other:  # avoid duplicate splits
                for vi, v in enumerate(nodes):
                    c = dp[sub][vi] + dp[other][vi]
                    if c < dp[mask][vi]:
                        dp[mask][vi] = c
            sub = (sub - 1) & mask
        # relax via shortest paths (one Dijkstra-like pass using dist matrix)
        new = list(dp[mask])
        for vi, v in enumerate(nodes):
            best = new[vi]
            for wi, w in enumerate(nodes):
                c = dp[mask][wi] + dist[w][v]
                if c < best:
                    best = c
            new[vi] = best
        dp[mask] = new
    return min(dp[(1 << k) - 1])


def test_steiner_line():
    nodes = ["a", "b", "c", "d"]
    edges = [("a", "b", 1), ("b", "c", 1), ("c", "d", 1)]
    assert dreyfus_wagner(nodes, edges, ["a", "d"]) == 3.0


def test_steiner_uses_steiner_point():
    # star: center x connects three terminals cheaper than pairwise
    nodes = ["t1", "t2", "t3", "x"]
    edges = [("t1", "x", 1), ("t2", "x", 1), ("t3", "x", 1),
             ("t1", "t2", 10), ("t2", "t3", 10), ("t1", "t3", 10)]
    assert dreyfus_wagner(nodes, edges, ["t1", "t2", "t3"]) == 3.0


def test_steiner_single_terminal():
    assert dreyfus_wagner(["a"], [], ["a"]) == 0.0


def test_steiner_two_terminals_is_shortest_path():
    nodes = ["a", "b", "c"]
    edges = [("a", "b", 2), ("b", "c", 2), ("a", "c", 10)]
    assert dreyfus_wagner(nodes, edges, ["a", "c"]) == 4.0


def test_steiner_all_terminals_is_mst():
    # all nodes terminal => Steiner tree = MST = 1 + 2 = 3.0
    edges = [("a", "b", 1), ("b", "c", 2), ("a", "c", 4)]
    nodes = ["a", "b", "c"]
    assert dreyfus_wagner(nodes, edges, nodes) == 3.0


def main() -> None:
    test_steiner_line()
    test_steiner_uses_steiner_point()
    test_steiner_single_terminal()
    test_steiner_two_terminals_is_shortest_path()
    test_steiner_all_terminals_is_mst()
    print("graph_47 (Steiner tree) OK")


if __name__ == "__main__":
    main()
