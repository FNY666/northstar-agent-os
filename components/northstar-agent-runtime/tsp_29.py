"""Euclidean TSP nearest-neighbor heuristic on a coordinate list (TSP-029), Simulated."""
from __future__ import annotations
import ast
import math

VERSION = "tsp-euclidean-nn.v1"


def _dist(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


def nearest_neighbor(coords, start=0):
    """Greedy nearest-neighbor tour from `start`. Returns (tour, length)."""
    n = len(coords)
    if n == 0:
        return ([], 0.0)
    tour = [start]
    used = {start}
    total = 0.0
    cur = start
    while len(tour) < n:
        nxt = min(
            (i for i in range(n) if i not in used),
            key=lambda i: (_dist(coords[cur], coords[i]), i),
        )
        total += _dist(coords[cur], coords[nxt])
        tour.append(nxt)
        used.add(nxt)
        cur = nxt
    total += _dist(coords[cur], coords[start])
    return (tour, total)


def main() -> None:
    # small instance: square, NN from 0 walks the perimeter
    coords = [(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)]
    tour, length = nearest_neighbor(coords)
    assert tour[0] == 0
    assert abs(length - 4.0) < 1e-9
    # degenerate cases
    assert nearest_neighbor([]) == ([], 0.0)
    assert nearest_neighbor([(2.0, 3.0)]) == ([0], 0.0)
    # correctness property: valid permutation, length matches recompute,
    # and NN from every start visits each point exactly once
    n = len(coords)
    assert sorted(tour) == list(range(n))
    assert abs(sum(_dist(coords[tour[i]], coords[tour[(i + 1) % n]]) for i in range(n)) - length) < 1e-9
    for s in range(n):
        ts, _ = nearest_neighbor(coords, start=s)
        assert sorted(ts) == list(range(n)) and ts[0] == s
    assert stdlib_only()
    print('tsp-euclidean-nn.v1 OK')


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
