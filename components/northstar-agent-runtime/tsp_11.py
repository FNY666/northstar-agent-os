"""Genetic algorithm TSP solver (TSP-011), Simulated."""
from __future__ import annotations
import ast
import random

VERSION = "tsp-genetic.v1"


def tour_length(dist: list[list[float]], tour: list[int]) -> float:
    n = len(tour)
    return sum(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))


def _ordered_crossover(rng: random.Random, a: list[int], b: list[int]) -> list[int]:
    n = len(a)
    i, j = sorted((rng.randrange(n), rng.randrange(n)))
    child = [-1] * n
    child[i : j + 1] = a[i : j + 1]
    fill = [x for x in b if x not in child]
    k = 0
    for p in range(n):
        if child[p] == -1:
            child[p] = fill[k]
            k += 1
    return child


def genetic_tsp(
    dist: list[list[float]],
    pop_size: int = 24,
    generations: int = 60,
    mutation_rate: float = 0.2,
    seed: int = 42,
) -> list[int]:
    """Genetic algorithm TSP: tour is a permutation of 0..n-1. Returns best tour."""
    rng = random.Random(seed)
    n = len(dist)
    if n == 0:
        return []
    if n == 1:
        return [0]
    pop = []
    for _ in range(pop_size):
        tour = list(range(n))
        rng.shuffle(tour)
        pop.append(tour)
    best = min(pop, key=lambda t: tour_length(dist, t))
    best_len = tour_length(dist, best)
    for _ in range(generations):
        next_pop = [best[:]]
        while len(next_pop) < pop_size:
            p1, p2 = min(rng.sample(pop, 3), key=lambda t: tour_length(dist, t)), min(
                rng.sample(pop, 3), key=lambda t: tour_length(dist, t)
            )
            child = _ordered_crossover(rng, p1, p2)
            if rng.random() < mutation_rate:
                i, j = rng.randrange(n), rng.randrange(n)
                child[i], child[j] = child[j], child[i]
            next_pop.append(child)
        pop = next_pop
        cand = min(pop, key=lambda t: tour_length(dist, t))
        cand_len = tour_length(dist, cand)
        if cand_len < best_len:
            best, best_len = cand, cand_len
    return best


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour = genetic_tsp(dist, seed=42)
    assert sorted(tour) == [0, 1, 2, 3], "valid tour must visit each city exactly once"
    assert tour_length(dist, tour) == 80, f"expected optimum 80, got {tour_length(dist, tour)}"
    assert genetic_tsp([], seed=1) == []
    assert genetic_tsp([[0]], seed=1) == [0]
    assert tour_length(dist, tour) == sum(
        dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour))
    )
    t1, t2 = genetic_tsp(dist, seed=7), genetic_tsp(dist, seed=7)
    assert t1 == t2, "fixed seed must be deterministic"
    assert stdlib_only()
    print("tsp-genetic.v1 OK")


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
