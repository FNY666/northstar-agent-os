"""Tour merge (combine two tours via best reconnection, mock) (TSP-034), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-tour-merge.v1"


def tour_cost(tour: list[int], dist: list[list[float]]) -> float:
    if not tour:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def _reverse_rotations(tour: list[int]):
    n = len(tour)
    for rev in (False, True):
        t = list(reversed(tour)) if rev else list(tour)
        for k in range(n):
            yield t[k:] + t[:k]


def merge_tours(t1: list[int], t2: list[int], dist: list[list[float]]) -> list[int]:
    """Combine two disjoint tours by cutting one edge from each and reconnecting
    the two paths with the two cheapest possible new edges (mock)."""
    if not t1:
        return list(t2)
    if not t2:
        return list(t1)
    best = list(t1) + list(t2)
    best_cost = tour_cost(best, dist)
    for a in _reverse_rotations(t1):
        for b in _reverse_rotations(t2):
            # a is a path a[0]..a[-1], b is a path b[0]..b[-1]
            cand = a + b
            c = tour_cost(cand, dist)
            if c < best_cost - 1e-12:
                best = cand
                best_cost = c
    return best


def main() -> None:
    dist = [
        [0, 1, 8, 8, 1],
        [1, 0, 1, 8, 8],
        [8, 1, 0, 1, 8],
        [8, 8, 1, 0, 1],
        [1, 8, 8, 1, 0],
    ]
    t1 = [0, 1]
    t2 = [2, 3, 4]
    merged = merge_tours(t1, t2, dist)
    assert sorted(merged) == list(range(5))  # covers every city exactly once
    assert tour_cost(merged, dist) <= tour_cost(t1 + t2, dist)  # never worse than naive concat
    # best reconnection: 0-1 and 2-3-4 join through 1-2 and 4-0 (cost 1+1+1+1+1=5)
    assert tour_cost(merged, dist) == 5

    # degenerate: empty or single-city tours
    assert merge_tours([], [0, 1], dist) == [0, 1]
    assert merge_tours([0, 1], [], dist) == [0, 1]
    assert merge_tours([], [], dist) == []

    # single-city merge still yields a valid permutation
    one = merge_tours([0], [1], dist)
    assert sorted(one) == [0, 1]

    assert stdlib_only()
    print('tsp-tour-merge.v1 OK')


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
