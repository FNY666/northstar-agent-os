"""Brute-force exact TSP via permutations (TSP-001), Simulated."""
from __future__ import annotations
import ast
import itertools

VERSION = "tsp-bruteforce.v1"


def tour_length(dist, tour):
    if len(tour) <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def solve_bruteforce(dist):
    """Return (best_tour, best_length); tour starts at city 0."""
    n = len(dist)
    if n == 0:
        return [], 0.0
    if n == 1:
        return [0], 0.0
    best_tour = None
    best_len = float("inf")
    for perm in itertools.permutations(range(1, n)):
        tour = [0] + list(perm)
        length = tour_length(dist, tour)
        if length < best_len:
            best_len = length
            best_tour = tour
    return best_tour, best_len


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour, length = solve_bruteforce(dist)
    # known optimum for this instance is 80 (tour 0-1-3-2-0)
    assert length == 80
    assert sorted(tour) == [0, 1, 2, 3]
    assert length == tour_length(dist, tour)
    assert solve_bruteforce([]) == ([], 0.0)
    assert solve_bruteforce([[0]]) == ([0], 0.0)
    tour2, length2 = solve_bruteforce([[0, 5], [5, 0]])
    assert sorted(tour2) == [0, 1] and length2 == 10
    assert stdlib_only()
    print('tsp-bruteforce.v1 OK')


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
