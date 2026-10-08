"""TSP benchmark runner (runs a registry of simple solvers on one instance, reports lengths) (TSP-046), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-benchmark.v1"

def tour_length(tour: list[int], dist: list[list[float]]) -> float:
    if len(tour) < 2:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))

def nearest_neighbor(dist: list[list[float]]) -> list[int]:
    n = len(dist)
    if n == 0:
        return []
    tour, seen = [0], {0}
    while len(tour) < n:
        last = tour[-1]
        nxt = min((c for c in range(n) if c not in seen), key=lambda c: dist[last][c])
        tour.append(nxt)
        seen.add(nxt)
    return tour

def cheapest_insertion(dist: list[list[float]]) -> list[int]:
    n = len(dist)
    if n == 0:
        return []
    tour = [0]
    for c in range(1, n):
        best_pos, best_cost = 0, float("inf")
        for pos in range(len(tour) + 1):
            a, b = tour[pos - 1], tour[pos] if pos < len(tour) else tour[0]
            cost = dist[a][c] + dist[c][b] - dist[a][b]
            if cost < best_cost:
                best_cost, best_pos = cost, pos
        tour = tour[:best_pos] + [c] + tour[best_pos:]
    return tour

def identity(dist: list[list[float]]) -> list[int]:
    return list(range(len(dist)))

SOLVERS = {"nearest-neighbor": nearest_neighbor, "cheapest-insertion": cheapest_insertion, "identity": identity}

def benchmark(dist: list[list[float]]) -> dict[str, float]:
    return {name: float(tour_length(fn(dist), dist)) for name, fn in SOLVERS.items()}

def main() -> None:
    d = [
        [0, 1, 4, 3],
        [1, 0, 2, 5],
        [4, 2, 0, 1],
        [3, 5, 1, 0],
    ]
    r = benchmark(d)
    assert set(r) == set(SOLVERS)
    assert all(isinstance(v, float) and v >= 0 for v in r.values())
    assert r["cheapest-insertion"] <= r["identity"] + 1e-9
    assert benchmark([]) == {k: 0.0 for k in SOLVERS}
    assert all(benchmark([[0]])[k] == 0.0 for k in SOLVERS)
    assert stdlib_only()
    print('tsp-benchmark.v1 OK')

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
