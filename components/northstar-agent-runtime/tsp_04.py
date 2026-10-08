"""Greedy (cheapest) insertion heuristic for TSP (TSP-004), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-greedy-insertion.v1"


def tour_length(dist, tour):
    if len(tour) <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def insertion_cost(dist, tour, city, pos):
    # insert city between tour[pos-1] and tour[pos] (cyclic indexing)
    n = len(tour)
    a = tour[pos - 1]
    b = tour[pos % n]
    return dist[a][city] + dist[city][b] - dist[a][b]


def solve_greedy_insertion(dist):
    """Repeatedly insert the city with the cheapest insertion cost."""
    n = len(dist)
    if n == 0:
        return [], 0.0
    if n == 1:
        return [0], 0.0
    tour = [0]
    unvisited = set(range(1, n))
    while unvisited:
        best_city, best_pos, best_cost = None, None, float("inf")
        for city in sorted(unvisited):
            for pos in range(len(tour)):
                cost = insertion_cost(dist, tour, city, pos)
                if cost < best_cost:
                    best_city, best_pos, best_cost = city, pos, cost
        tour.insert(best_pos, best_city)
        unvisited.discard(best_city)
    return tour, tour_length(dist, tour)


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour, length = solve_greedy_insertion(dist)
    assert sorted(tour) == [0, 1, 2, 3]
    assert length == tour_length(dist, tour)
    assert length >= 80  # cannot beat the known optimum
    assert solve_greedy_insertion([]) == ([], 0.0)
    assert solve_greedy_insertion([[0]]) == ([0], 0.0)
    tour2, length2 = solve_greedy_insertion([[0, 5], [5, 0]])
    assert sorted(tour2) == [0, 1] and length2 == 10
    # points on a line: cheapest insertion finds the optimum 2*(n-1)
    line = [[abs(i - j) for j in range(4)] for i in range(4)]
    ltour, llength = solve_greedy_insertion(line)
    assert sorted(ltour) == [0, 1, 2, 3] and llength == 6
    assert stdlib_only()
    print('tsp-greedy-insertion.v1 OK')


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
