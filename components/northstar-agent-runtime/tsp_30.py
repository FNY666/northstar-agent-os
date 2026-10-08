"""k-opt edge-swap improvement: random 2-opt hill climbing with fixed seed (TSP-030), Simulated."""
from __future__ import annotations
import ast
import random

VERSION = "tsp-k-opt.v1"


def tour_length(tour, dist):
    n = len(tour)
    if n <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))


def k_opt(dist, seed=12345, max_iter=200):
    """Mock k-opt: shuffle with a fixed seed, then hill-climb with random
    2-opt moves (k=2 edge swaps) until no improvement. Deterministic."""
    rng = random.Random(seed)
    n = len(dist)
    if n <= 1:
        return (list(range(n)), 0.0)
    tour = list(range(n))
    rng.shuffle(tour)
    best = tour_length(tour, dist)
    improved = True
    it = 0
    while improved and it < max_iter:
        improved = False
        it += 1
        for _ in range(n * n):
            i = rng.randrange(n)
            j = rng.randrange(n)
            if i == j:
                continue
            a, b = (i, j) if i < j else (j, i)
            if b == a + 1:
                continue
            new = tour[: a + 1] + tour[a + 1 : b + 1][::-1] + tour[b + 1 :]
            nl = tour_length(new, dist)
            if nl < best - 1e-12:
                tour, best = new, nl
                improved = True
                break
    return (tour, best)


def main() -> None:
    dist = [
        [0, 10, 15, 20, 12],
        [10, 0, 35, 25, 18],
        [15, 35, 0, 30, 22],
        [20, 25, 30, 0, 14],
        [12, 18, 22, 14, 0],
    ]
    n = len(dist)
    tour, length = k_opt(dist, seed=7)
    # small instance runs and returns a full tour
    assert sorted(tour) == list(range(n))
    assert abs(tour_length(tour, dist) - length) < 1e-9
    # degenerate cases
    assert k_opt([], seed=7) == ([], 0.0)
    assert k_opt([[0]], seed=7) == ([0], 0.0)
    # correctness property: deterministic and never worse than the seeded
    # initial shuffle it started from
    tour2, length2 = k_opt(dist, seed=7)
    assert tour2 == tour and length2 == length
    rng = random.Random(7)
    init = list(range(n))
    rng.shuffle(init)
    assert length <= tour_length(init, dist) + 1e-9
    assert stdlib_only()
    print('tsp-k-opt.v1 OK')


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
