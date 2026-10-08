"""Simulated annealing for TSP (TSP-010), Simulated."""
from __future__ import annotations
import ast
import math
import random

VERSION = "tsp-simulated-annealing.v1"


def tour_length(dist, tour):
    if len(tour) <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def solve_simulated_annealing(dist, seed=42, iters=2000, t0=10.0, cooling=0.995):
    """Simulated annealing with random 2-opt moves; deterministic given seed."""
    n = len(dist)
    if n == 0:
        return [], 0.0
    if n == 1:
        return [0], 0.0
    rng = random.Random(seed)
    cur = list(range(n))
    rng.shuffle(cur)
    cur_len = tour_length(dist, cur)
    best, best_len = list(cur), cur_len
    if n > 2:
        temp = t0
        for _ in range(iters):
            i = rng.randrange(1, n - 1)
            j = rng.randrange(i + 1, n)
            cand = cur[:i] + cur[i:j + 1][::-1] + cur[j + 1:]
            cand_len = tour_length(dist, cand)
            if cand_len < cur_len or rng.random() < math.exp((cur_len - cand_len) / temp):
                cur, cur_len = cand, cand_len
                if cand_len < best_len:
                    best, best_len = cand, cand_len
            temp = max(temp * cooling, 1e-6)
    return best, best_len


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour, length = solve_simulated_annealing(dist)
    assert sorted(tour) == [0, 1, 2, 3]
    assert length == tour_length(dist, tour)
    assert length >= 80  # cannot beat the known optimum
    assert length <= 95  # never worse than the worst tour on this instance
    # determinism: same seed gives the same result
    tour_b, length_b = solve_simulated_annealing(dist)
    assert tour_b == tour and length_b == length
    assert solve_simulated_annealing([]) == ([], 0.0)
    assert solve_simulated_annealing([[0]]) == ([0], 0.0)
    tour2, length2 = solve_simulated_annealing([[0, 5], [5, 0]], seed=7)
    assert sorted(tour2) == [0, 1] and length2 == 10
    # a different seed still yields a valid tour
    tour3, length3 = solve_simulated_annealing(dist, seed=123)
    assert sorted(tour3) == [0, 1, 2, 3] and length3 == tour_length(dist, tour3)
    assert stdlib_only()
    print('tsp-simulated-annealing.v1 OK')


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
