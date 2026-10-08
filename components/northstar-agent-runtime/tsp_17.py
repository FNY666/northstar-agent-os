"""Double-tree (MST doubling) TSP approximation heuristic (TSP-017), Simulated."""
from __future__ import annotations
import ast
import heapq

VERSION = "tsp-double-tree.v1"


def prim_mst_parent(dist: list[list[float]]) -> list[int]:
    n = len(dist)
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
    return parent


def double_tree_tsp(dist: list[list[float]]) -> list[int]:
    """Double-tree approximation: build MST, do a DFS preorder traversal, then
    shortcut repeated vertices. 2-approximation for metric TSP."""
    n = len(dist)
    if n == 0:
        return []
    if n == 1:
        return [0]
    parent = prim_mst_parent(dist)
    children = [[] for _ in range(n)]
    for v in range(1, n):
        children[parent[v]].append(v)
    preorder = []

    def dfs(u: int) -> None:
        preorder.append(u)
        for c in children[u]:
            dfs(c)

    dfs(0)
    return preorder


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
    tour = double_tree_tsp(dist)
    assert sorted(tour) == [0, 1, 2, 3], "valid tour must visit each city exactly once"
    length = tour_length(dist, tour)
    assert length <= 2 * 80.0, "double-tree must stay within the 2x approximation guarantee"
    assert double_tree_tsp([]) == []
    assert double_tree_tsp([[0]]) == [0]
    assert length == sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))
    metric = [
        [0, 1, 2, 3],
        [1, 0, 1, 2],
        [2, 1, 0, 1],
        [3, 2, 1, 0],
    ]
    tm = double_tree_tsp(metric)
    assert tour_length(metric, tm) == 6.0, f"expected 6 on line metric, got {tour_length(metric, tm)}"
    assert stdlib_only()
    print("tsp-double-tree.v1 OK")


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
