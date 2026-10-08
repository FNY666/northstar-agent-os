"""1-tree lower bound (Held-Karp style bound) for TSP (TSP-016), Simulated."""
from __future__ import annotations
import ast
import heapq

VERSION = "tsp-one-tree-bound.v1"


def prim_mst_weight(dist: list[list[float]], nodes: list[int]) -> float:
    if len(nodes) <= 1:
        return 0.0
    idx = {v: k for k, v in enumerate(nodes)}
    m = len(nodes)
    in_tree = [False] * m
    best = [float("inf")] * m
    best[0] = 0.0
    heap = [(0.0, 0)]
    total = 0.0
    while heap:
        d, u = heapq.heappop(heap)
        if in_tree[u]:
            continue
        in_tree[u] = True
        total += d
        for v in range(m):
            if not in_tree[v]:
                w = dist[nodes[u]][nodes[v]]
                if w < best[v]:
                    best[v] = w
                    heapq.heappush(heap, (w, v))
    return total


def one_tree_bound(dist: list[list[float]]) -> float:
    """1-tree bound: MST over nodes 1..n-1 plus the two cheapest edges incident
    to node 0. A valid lower bound for the symmetric TSP optimum."""
    n = len(dist)
    if n == 0:
        return 0.0
    if n == 1:
        return 0.0
    rest = list(range(1, n))
    mst = prim_mst_weight(dist, rest)
    two = sorted(dist[0][j] for j in rest)[:2]
    return mst + sum(two)


def tour_length(dist: list[list[float]], tour: list[int]) -> float:
    n = len(tour)
    return sum(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    bound = one_tree_bound(dist)
    assert bound == 80.0, f"expected 1-tree bound 80, got {bound}"
    assert bound <= 80.0, "1-tree bound must not exceed optimal tour 80"
    assert one_tree_bound([]) == 0.0
    assert one_tree_bound([[0]]) == 0.0
    two = [[0, 3], [3, 0]]
    assert one_tree_bound(two) == 3.0, f"2-node bound: single distinct edge, got {one_tree_bound(two)}"
    mst_only = prim_mst_weight(dist, list(range(1, 4)))
    assert mst_only == 55.0, f"MST on nodes 1..3 should be 55, got {mst_only}"
    assert stdlib_only()
    print("tsp-one-tree-bound.v1 OK")


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
