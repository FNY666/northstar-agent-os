"""Bottleneck traveling salesman: minimize the maximum edge on the tour (TSP-021), Simulated."""
from __future__ import annotations
import ast
import itertools

VERSION = "tsp-bottleneck.v1"


def tour_bottleneck(tour, dist):
    n = len(tour)
    if n <= 1:
        return 0.0
    return max(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))


def bottleneck_tsp(dist):
    """Exact bottleneck TSP via threshold search: try edge-weight thresholds
    in ascending order and return the first threshold that admits a tour."""
    n = len(dist)
    if n == 0:
        return ([], 0.0)
    if n == 1:
        return ([0], 0.0)
    thresholds = sorted({dist[i][j] for i in range(n) for j in range(n) if i != j})
    for t in thresholds:
        ok = [[dist[i][j] <= t for j in range(n)] for i in range(n)]
        for perm in itertools.permutations(range(1, n)):
            tour = (0,) + perm
            if all(ok[tour[i]][tour[(i + 1) % n]] for i in range(n)):
                return (list(tour), t)
    raise AssertionError("unreachable: complete graph always admits a tour")


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour, b = bottleneck_tsp(dist)
    # small instance: optimum equals brute force over all tours
    brute = min(
        tour_bottleneck((0,) + p, dist)
        for p in itertools.permutations(range(1, 4))
    )
    assert b == brute
    # degenerate cases
    assert bottleneck_tsp([]) == ([], 0.0)
    assert bottleneck_tsp([[0]]) == ([0], 0.0)
    # correctness property: returned bottleneck matches the tour and is
    # no worse than an arbitrary tour
    assert sorted(tour) == [0, 1, 2, 3]
    assert tour_bottleneck(tour, dist) == b
    assert b <= tour_bottleneck([0, 1, 2, 3], dist)
    assert stdlib_only()
    print('tsp-bottleneck.v1 OK')


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
