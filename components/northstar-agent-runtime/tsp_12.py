"""Ant-colony-style constructive TSP heuristic (TSP-012), Simulated."""
from __future__ import annotations
import ast
import random

VERSION = "tsp-ant-colony.v1"


def tour_length(dist: list[list[float]], tour: list[int]) -> float:
    n = len(tour)
    return sum(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))


def ant_colony_tsp(
    dist: list[list[float]],
    n_ants: int = 10,
    iterations: int = 40,
    alpha: float = 1.0,
    beta: float = 2.0,
    evaporation: float = 0.5,
    seed: int = 123,
) -> list[int]:
    """Ant-colony-style heuristic: probabilistic construction guided by pheromones.
    Returns the best tour found; not exact, so marked heuristic."""
    rng = random.Random(seed)
    n = len(dist)
    if n == 0:
        return []
    if n == 1:
        return [0]
    pher = [[1.0] * n for _ in range(n)]
    best_tour: list[int] = []
    best_len = float("inf")
    for _ in range(iterations):
        for _ in range(n_ants):
            start = rng.randrange(n)
            tour = [start]
            unvisited = set(range(n))
            unvisited.discard(start)
            while unvisited:
                cur = tour[-1]
                weights = [
                    (pher[cur][j] ** alpha) * ((1.0 / max(dist[cur][j], 1e-9)) ** beta)
                    for j in unvisited
                ]
                total = sum(weights)
                r = rng.random() * total
                acc = 0.0
                chosen = -1
                for j, w in zip(sorted(unvisited), weights):
                    acc += w
                    if r <= acc:
                        chosen = j
                        break
                if chosen == -1:
                    chosen = sorted(unvisited)[-1]
                tour.append(chosen)
                unvisited.discard(chosen)
            length = tour_length(dist, tour)
            if length < best_len:
                best_tour, best_len = tour, length
            deposit = 1.0 / max(length, 1e-9)
            for i in range(n):
                pher[tour[i]][tour[(i + 1) % n]] += deposit
                pher[tour[(i + 1) % n]][tour[i]] += deposit
        for i in range(n):
            for j in range(n):
                pher[i][j] *= 1.0 - evaporation
    return best_tour


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour = ant_colony_tsp(dist, seed=123)
    assert sorted(tour) == [0, 1, 2, 3], "valid tour must visit each city exactly once"
    assert tour_length(dist, tour) == 80, f"heuristic should hit optimum 80 here, got {tour_length(dist, tour)}"
    assert ant_colony_tsp([], seed=1) == []
    assert ant_colony_tsp([[0]], seed=1) == [0]
    assert tour_length(dist, tour) == sum(
        dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour))
    )
    assert ant_colony_tsp(dist, seed=5) == ant_colony_tsp(dist, seed=5), "fixed seed deterministic"
    assert stdlib_only()
    print("tsp-ant-colony.v1 OK")


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
