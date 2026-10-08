"""Dynamic TSP re-optimization (mock: reinsert changed city) (TSP-042), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-dynamic.v1"

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

def tour_length(tour: list[int], dist: list[list[float]]) -> float:
    if len(tour) < 2:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))

def reoptimize(tour: list[int], dist: list[list[float]], changed: int) -> list[int]:
    """Remove `changed` from tour, reinsert at the cheapest position."""
    if changed not in tour:
        return list(tour)
    rest = [c for c in tour if c != changed]
    if not rest:
        return [changed]
    best_pos, best_cost = 0, float("inf")
    n = len(rest)
    for pos in range(n):
        a, b = rest[pos - 1], rest[pos % n]
        cost = dist[a][changed] + dist[changed][b] - dist[a][b]
        if cost < best_cost:
            best_cost, best_pos = cost, pos
    return rest[:best_pos] + [changed] + rest[best_pos:]

def main() -> None:
    d = [
        [0, 1, 9, 3],
        [1, 0, 2, 9],
        [9, 2, 0, 1],
        [3, 9, 1, 0],
    ]
    t = nearest_neighbor(d)
    assert sorted(t) == [0, 1, 2, 3]
    t2 = reoptimize(t, d, 2)
    assert sorted(t2) == [0, 1, 2, 3]
    assert tour_length(t2, d) <= tour_length(t, d) + 1e-9
    assert reoptimize([], d, 0) == []
    assert reoptimize([0], [[0]], 0) == [0]
    assert stdlib_only()
    print('tsp-dynamic.v1 OK')

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
