"""Branch-and-bound TSP with MST-based pruning (TSP-014), Simulated."""
from __future__ import annotations
import ast
import heapq

VERSION = "tsp-branch-bound.v1"


def _prim_mst(dist: list[list[float]], nodes: list[int]) -> float:
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


def _partial_tour_bound(
    dist: list[list[float]], path: list[int], visited: list[bool], cost: float
) -> float:
    """Valid lower bound: cost so far + MST over remaining + cheapest edge
    leaving the path end into remaining + cheapest edge from remaining back
    to any visited city."""
    n = len(dist)
    remaining = [j for j in range(n) if not visited[j]]
    if not remaining:
        return cost
    mst = _prim_mst(dist, remaining)
    last = path[-1]
    min_out = min(dist[last][j] for j in remaining)
    min_back = min(dist[j][v] for j in remaining for v in range(n) if visited[v])
    return cost + mst + min_out + min_back


def branch_bound_tsp(dist: list[list[float]]) -> list[int]:
    """Mock branch-and-bound: DFS over partial tours with 1-tree (MST-based)
    lower-bound pruning. Exact on small symmetric instances."""
    n = len(dist)
    if n == 0:
        return []
    if n == 1:
        return [0]
    best_tour = list(range(n))
    best_len = sum(dist[best_tour[i]][best_tour[(i + 1) % n]] for i in range(n))

    def dfs(path: list[int], visited: list[bool], cost: float) -> None:
        nonlocal best_tour, best_len
        if len(path) == n:
            total = cost + dist[path[-1]][path[0]]
            if total < best_len:
                best_tour, best_len = path[:], total
            return
        bound = _partial_tour_bound(dist, path, visited, cost)
        if bound >= best_len:
            return
        last = path[-1]
        for nxt in range(n):
            if not visited[nxt]:
                if cost + dist[last][nxt] >= best_len:
                    continue
                visited[nxt] = True
                path.append(nxt)
                dfs(path, visited, cost + dist[last][nxt])
                path.pop()
                visited[nxt] = False

    visited = [False] * n
    visited[0] = True
    dfs([0], visited, 0.0)
    return best_tour


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
    tour = branch_bound_tsp(dist)
    assert sorted(tour) == [0, 1, 2, 3], "valid tour must visit each city exactly once"
    assert tour_length(dist, tour) == 80, f"expected exact optimum 80, got {tour_length(dist, tour)}"
    assert branch_bound_tsp([]) == []
    assert branch_bound_tsp([[0]]) == [0]
    assert tour_length(dist, tour) == sum(
        dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour))
    )
    five = [
        [0, 2, 9, 10, 7],
        [2, 0, 6, 4, 3],
        [9, 6, 0, 8, 5],
        [10, 4, 8, 0, 6],
        [7, 3, 5, 6, 0],
    ]
    t5 = branch_bound_tsp(five)
    assert tour_length(five, t5) == 26, f"expected exact 26, got {tour_length(five, t5)}"
    assert stdlib_only()
    print("tsp-branch-bound.v1 OK")


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
