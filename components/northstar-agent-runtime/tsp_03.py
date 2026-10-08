"""Nearest-neighbor heuristic for TSP (TSP-003), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-nearest-neighbor.v1"


def tour_length(dist, tour):
    if len(tour) <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def solve_nearest_neighbor(dist):
    """Greedy nearest neighbor from every start city; keep the best tour."""
    n = len(dist)
    if n == 0:
        return [], 0.0
    if n == 1:
        return [0], 0.0
    best_tour = None
    best_len = float("inf")
    for start in range(n):
        unvisited = set(range(n))
        unvisited.discard(start)
        tour = [start]
        while unvisited:
            cur = tour[-1]
            nxt = min(unvisited, key=lambda c: dist[cur][c])
            tour.append(nxt)
            unvisited.discard(nxt)
        length = tour_length(dist, tour)
        if length < best_len:
            best_tour, best_len = tour, length
    return best_tour, best_len


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour, length = solve_nearest_neighbor(dist)
    # heuristic must return a valid tour whose length matches its edge sum
    assert sorted(tour) == [0, 1, 2, 3]
    assert length == tour_length(dist, tour)
    # heuristic can never beat the known optimum of 80
    assert length >= 80
    assert solve_nearest_neighbor([]) == ([], 0.0)
    assert solve_nearest_neighbor([[0]]) == ([0], 0.0)
    # points on a line: nearest neighbor finds the optimum 2*(n-1)
    line = [[abs(i - j) for j in range(4)] for i in range(4)]
    ltour, llength = solve_nearest_neighbor(line)
    assert sorted(ltour) == [0, 1, 2, 3] and llength == 6
    assert stdlib_only()
    print('tsp-nearest-neighbor.v1 OK')


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
