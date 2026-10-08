"""Stochastic TSP (mock: expected length under edge noise, fixed seed) (TSP-043), Simulated."""
from __future__ import annotations
import ast
import random

VERSION = "tsp-stochastic.v1"

def expected_length(tour: list[int], dist: list[list[float]], sigma: float, samples: int = 200, seed: int = 7) -> float:
    """Monte-Carlo expected tour length under Gaussian edge noise."""
    rng = random.Random(seed)
    if len(tour) < 2:
        return 0.0
    n = len(tour)
    total = 0.0
    for _ in range(samples):
        for i in range(n):
            base = dist[tour[i]][tour[(i + 1) % n]]
            total += base + rng.gauss(0.0, sigma)
    return total / samples

def deterministic_length(tour: list[int], dist: list[list[float]]) -> float:
    if len(tour) < 2:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))

def main() -> None:
    d = [
        [0, 1, 4, 3],
        [1, 0, 2, 5],
        [4, 2, 0, 1],
        [3, 5, 1, 0],
    ]
    tour = [0, 1, 2, 3]
    det = deterministic_length(tour, d)
    exp_len = expected_length(tour, d, sigma=0.5)
    assert abs(exp_len - det) < 1.0, (exp_len, det)
    # fixed seed -> deterministic result
    assert expected_length(tour, d, 0.5) == exp_len
    assert expected_length([], d, 0.5) == 0.0
    assert expected_length([0], [[0]], 0.5) == 0.0
    assert stdlib_only()
    print('tsp-stochastic.v1 OK')

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
