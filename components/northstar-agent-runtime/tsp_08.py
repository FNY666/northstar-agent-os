"""2-opt local search improvement for TSP tours (TSP-008), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-2opt.v1"


def tour_length(dist, tour):
    if len(tour) <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def two_opt_swap(tour, i, j):
    # reverse the segment tour[i..j]; city 0 stays fixed by using i >= 1
    return tour[:i] + tour[i:j + 1][::-1] + tour[j + 1:]


def improve_2opt(dist, tour):
    """Repeatedly apply the best 2-opt move until no improvement remains."""
    n = len(tour)
    if n <= 2:
        return list(tour), tour_length(dist, tour)
    best = list(tour)
    best_len = tour_length(dist, best)
    improved = True
    while improved:
        improved = False
        for i in range(1, n - 1):
            for j in range(i + 1, n):
                cand = two_opt_swap(best, i, j)
                cand_len = tour_length(dist, cand)
                if cand_len < best_len - 1e-9:
                    best, best_len = cand, cand_len
                    improved = True
    return best, best_len


def is_2opt(tour, dist):
    # property check: no single 2-opt move improves the tour
    n = len(tour)
    base = tour_length(dist, tour)
    for i in range(1, n - 1):
        for j in range(i + 1, n):
            if tour_length(dist, two_opt_swap(tour, i, j)) < base - 1e-9:
                return False
    return True


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    # worst tour for this instance: 0-2-1-3-0 = 15+35+25+20 = 95
    start = [0, 2, 1, 3]
    assert tour_length(dist, start) == 95
    tour, length = improve_2opt(dist, start)
    assert sorted(tour) == [0, 1, 2, 3]
    assert length == 80  # reaches the known optimum
    assert length == tour_length(dist, tour)
    assert is_2opt(tour, dist)  # 2-opt local optimality property
    assert improve_2opt(dist, [0]) == ([0], 0.0)
    assert improve_2opt(dist, []) == ([], 0.0)
    # an already-optimal tour is unchanged
    opt_tour, opt_len = improve_2opt(dist, [0, 1, 3, 2])
    assert opt_len == 80 and sorted(opt_tour) == [0, 1, 2, 3]
    assert stdlib_only()
    print('tsp-2opt.v1 OK')


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
