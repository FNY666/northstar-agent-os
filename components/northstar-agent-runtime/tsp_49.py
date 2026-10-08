"""Random tour + repair + 2-opt pipeline (TSP-049), Simulated."""
from __future__ import annotations
import ast
import random

VERSION = "tsp-pipeline.v1"

def tour_length(tour: list[int], dist: list[list[float]]) -> float:
    if len(tour) < 2:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))

def repair(tour: list[int], n: int) -> list[int]:
    seen: set[int] = set()
    fixed = [c for c in tour if 0 <= c < n and not (c in seen or seen.add(c))]
    return fixed + [c for c in range(n) if c not in seen]

def two_opt(tour: list[int], dist: list[list[float]]) -> list[int]:
    n = len(tour)
    if n < 4:
        return list(tour)
    improved = True
    tour = list(tour)
    while improved:
        improved = False
        for i in range(n - 1):
            for j in range(i + 2, n):
                if i == 0 and j == n - 1:
                    continue
                a, b = tour[i], tour[(i + 1) % n]
                c, d = tour[j], tour[(j + 1) % n]
                if dist[a][c] + dist[b][d] < dist[a][b] + dist[c][d] - 1e-12:
                    tour[i + 1:j + 1] = reversed(tour[i + 1:j + 1])
                    improved = True
    return tour

def pipeline(dist: list[list[float]], seed: int = 3) -> list[int]:
    n = len(dist)
    rng = random.Random(seed)
    tour = list(range(n))
    rng.shuffle(tour)
    tour = repair(tour, n)
    return two_opt(tour, dist)

def main() -> None:
    d = [
        [0, 1, 4, 3],
        [1, 0, 2, 5],
        [4, 2, 0, 1],
        [3, 5, 1, 0],
    ]
    rng = random.Random(3)
    raw = list(range(4))
    rng.shuffle(raw)
    raw_len = tour_length(raw, d)
    t = pipeline(d, seed=3)
    assert sorted(t) == [0, 1, 2, 3]
    assert tour_length(t, d) <= raw_len + 1e-9
    # determinism under same seed
    assert pipeline(d, seed=3) == t
    assert pipeline([], seed=3) == []
    assert pipeline([[0]], seed=3) == [0]
    assert stdlib_only()
    print('tsp-pipeline.v1 OK')

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
