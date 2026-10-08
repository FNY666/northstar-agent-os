"""Nearest insertion heuristic for TSP (TSP-006), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-nearest-insertion.v1"


def tour_length(dist, tour):
    if len(tour) <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def insertion_cost(dist, tour, city, pos):
    n = len(tour)
    a = tour[pos - 1]
    b = tour[pos % n]
    return dist[a][city] + dist[city][b] - dist[a][b]


def solve_nearest_insertion(dist):
    """Repeatedly insert the unvisited city nearest to the current tour."""
    n = len(dist)
    if n == 0:
        return [], 0.0
    if n == 1:
        return [0], 0.0
    tour = [0]
    unvisited = set(range(1, n))
    while unvisited:
        # nearest city: minimizes its minimum distance to the tour
        nearest = min(sorted(unvisited), key=lambda c: min(dist[c][t] for t in tour))
        best_pos = min(range(len(tour)), key=lambda p: insertion_cost(dist, tour, nearest, p))
        tour.insert(best_pos, nearest)
        unvisited.discard(nearest)
    return tour, tour_length(dist, tour)


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour, length = solve_nearest_insertion(dist)
    assert sorted(tour) == [0, 1, 2, 3]
    assert length == tour_length(dist, tour)
    assert length >= 80  # cannot beat the known optimum
    assert solve_nearest_insertion([]) == ([], 0.0)
    assert solve_nearest_insertion([[0]]) == ([0], 0.0)
    tour2, length2 = solve_nearest_insertion([[0, 5], [5, 0]])
    assert sorted(tour2) == [0, 1] and length2 == 10
    # points on a line: nearest insertion finds the optimum 2*(n-1)
    line = [[abs(i - j) for j in range(4)] for i in range(4)]
    ltour, llength = solve_nearest_insertion(line)
    assert sorted(ltour) == [0, 1, 2, 3] and llength == 6
    assert stdlib_only()
    print('tsp-nearest-insertion.v1 OK')


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
