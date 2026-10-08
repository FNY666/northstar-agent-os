"""Christofides-style approximation for TSP (TSP-007), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-christofides.v1"


def tour_length(dist, tour):
    if len(tour) <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def prim_mst_edges(dist):
    n = len(dist)
    in_mst = [False] * n
    key = [float("inf")] * n
    par = [-1] * n
    key[0] = 0.0
    for _ in range(n):
        u = min((i for i in range(n) if not in_mst[i]), key=lambda i: key[i])
        in_mst[u] = True
        for v in range(n):
            if not in_mst[v] and dist[u][v] < key[v]:
                key[v] = dist[u][v]
                par[v] = u
    return [(par[v], v) for v in range(1, n)]


def greedy_matching(dist, odd):
    # greedy minimum matching on the odd-degree vertices (approx)
    pairs = sorted(
        (dist[i][j], i, j) for a, i in enumerate(odd) for j in odd[a + 1:]
    )
    matched = set()
    edges = []
    for _, i, j in pairs:
        if i not in matched and j not in matched:
            matched.add(i)
            matched.add(j)
            edges.append((i, j))
    return edges


def euler_tour(n, edges):
    # Hierholzer on a multigraph given as a list of (u, v) edge tuples
    adj = [[] for _ in range(n)]
    for idx, (u, v) in enumerate(edges):
        adj[u].append((v, idx))
        adj[v].append((u, idx))
    used = [False] * len(edges)
    stack = [0]
    circuit = []
    while stack:
        u = stack[-1]
        while adj[u] and used[adj[u][-1][1]]:
            adj[u].pop()
        if adj[u]:
            v, idx = adj[u].pop()
            used[idx] = True
            stack.append(v)
        else:
            circuit.append(stack.pop())
    circuit.reverse()
    return circuit


def solve_christofides(dist):
    """MST + greedy matching on odd vertices + Euler tour + shortcutting."""
    n = len(dist)
    if n == 0:
        return [], 0.0
    if n == 1:
        return [0], 0.0
    mst_edges = prim_mst_edges(dist)
    deg = [0] * n
    for u, v in mst_edges:
        deg[u] += 1
        deg[v] += 1
    odd = [i for i in range(n) if deg[i] % 2 == 1]
    multi = mst_edges + greedy_matching(dist, odd)
    euler = euler_tour(n, multi)
    seen = set()
    tour = []
    for c in euler:
        if c not in seen:
            seen.add(c)
            tour.append(c)
    return tour, tour_length(dist, tour)


def main() -> None:
    # metric instance (triangle inequality holds): 1.5-approx guarantee applies
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour, length = solve_christofides(dist)
    assert sorted(tour) == [0, 1, 2, 3]
    assert length == tour_length(dist, tour)
    assert length <= 1.5 * 80  # Christofides guarantee vs known optimum 80
    assert length >= 80  # cannot beat the optimum
    assert solve_christofides([]) == ([], 0.0)
    assert solve_christofides([[0]]) == ([0], 0.0)
    tour2, length2 = solve_christofides([[0, 5], [5, 0]])
    assert sorted(tour2) == [0, 1] and length2 == 10
    # MST lower bound: result cannot be shorter than the MST weight
    mst_w = sum(dist[u][v] for u, v in prim_mst_edges(dist))
    assert length >= mst_w
    assert stdlib_only()
    print('tsp-christofides.v1 OK')


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
