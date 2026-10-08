"""TSP with precedence constraints (mock: topological-respecting insertion) (TSP-041), Simulated."""
from __future__ import annotations
import ast
from collections import defaultdict

VERSION = "tsp-precedence.v1"

def solve(dist: list[list[float]], prec: list[tuple[int, int]]) -> list[int]:
    """Nearest-insertion tour honoring precedence (a before b) pairs."""
    n = len(dist)
    if n == 0:
        return []
    if n == 1:
        return [0]
    remaining = set(range(n))
    tour = [0]
    remaining.discard(0)
    while remaining:
        best = None
        best_cost = float("inf")
        for c in sorted(remaining):
            for pos in range(len(tour) + 1):
                cand = tour[:pos] + [c] + tour[pos:]
                if not respects(cand, prec):
                    continue
                cost = insertion_cost(tour, c, pos, dist)
                if cost < best_cost:
                    best_cost = cost
                    best = (c, pos)
        if best is None:
            # fall back: append respecting prec if possible
            for c in sorted(remaining):
                if respects(tour + [c], prec):
                    tour.append(c)
                    remaining.discard(c)
                    break
            else:
                raise ValueError("infeasible precedence")
        else:
            c, pos = best
            tour = tour[:pos] + [c] + tour[pos:]
            remaining.discard(c)
    return tour

def insertion_cost(tour: list[int], c: int, pos: int, dist: list[list[float]]) -> float:
    if not tour:
        return 0.0
    a = tour[pos - 1]
    b = tour[pos] if pos < len(tour) else tour[0]
    return dist[a][c] + dist[c][b] - dist[a][b]

def respects(tour: list[int], prec: list[tuple[int, int]]) -> bool:
    pos = {c: i for i, c in enumerate(tour)}
    return all(pos[a] < pos[b] for a, b in prec if a in pos and b in pos)

def tour_length(tour: list[int], dist: list[list[float]]) -> float:
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
    t = solve(d, [(0, 2), (1, 3)])
    assert sorted(t) == [0, 1, 2, 3], t
    p = {c: i for i, c in enumerate(t)}
    assert p[0] < p[2] and p[1] < p[3], t
    assert tour_length(t, d) > 0
    assert solve([], []) == []
    assert solve([[0]], []) == [0]
    assert stdlib_only()
    print('tsp-precedence.v1 OK')

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
