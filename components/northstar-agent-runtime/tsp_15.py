"""MST lower bound computation for TSP (TSP-015), Simulated."""
from __future__ import annotations
import ast
import heapq

VERSION = "tsp-mst-lower-bound.v1"


def prim_mst(dist: list[list[float]]) -> tuple[list[int], float]:
    """Prim's MST. Returns (parent list, total weight)."""
    n = len(dist)
    if n == 0:
        return [], 0.0
    if n == 1:
        return [-1], 0.0
    parent = [-1] * n
    key = [float("inf")] * n
    key[0] = 0.0
    in_tree = [False] * n
    heap = [(0.0, 0)]
    while heap:
        d, u = heapq.heappop(heap)
        if in_tree[u]:
            continue
        in_tree[u] = True
        for v in range(n):
            w = dist[u][v]
            if u != v and not in_tree[v] and w < key[v]:
                key[v] = w
                parent[v] = u
                heapq.heappush(heap, (w, v))
    total = sum(dist[v][parent[v]] for v in range(1, n))
    return parent, total


def mst_lower_bound(dist: list[list[float]]) -> float:
    """MST weight is a valid lower bound for the optimal symmetric TSP tour."""
    _, total = prim_mst(dist)
    return total


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
    bound = mst_lower_bound(dist)
    assert bound == 45.0, f"expected MST weight 45, got {bound}"
    assert bound <= 80.0, "MST weight must not exceed optimal tour 80"
    assert mst_lower_bound([]) == 0.0
    assert mst_lower_bound([[0]]) == 0.0
    parent, total = prim_mst(dist)
    assert len(parent) == 4 and parent[0] == -1
    assert total == bound == sum(dist[v][parent[v]] for v in range(1, 4))
    two = [[0, 3], [3, 0]]
    assert mst_lower_bound(two) == 3.0, "2-node MST weight equals the single edge"
    assert stdlib_only()
    print("tsp-mst-lower-bound.v1 OK")


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
