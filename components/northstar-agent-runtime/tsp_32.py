"""Node interchange (swap two cities) improvement (TSP-032), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-node-interchange.v1"


def tour_cost(tour: list[int], dist: list[list[float]]) -> float:
    if not tour:
        return 0.0
    total = 0.0
    for i in range(len(tour)):
        total += dist[tour[i]][tour[(i + 1) % len(tour)]]
    return total


def node_interchange(tour: list[int], dist: list[list[float]]) -> list[int]:
    """Swap pairs of cities while any swap strictly reduces the tour cost."""
    if len(tour) < 2:
        return list(tour)
    best = list(tour)
    best_cost = tour_cost(best, dist)
    n = len(best)
    improved = True
    while improved:
        improved = False
        for i in range(n):
            for j in range(i + 1, n):
                cand = list(best)
                cand[i], cand[j] = cand[j], cand[i]
                c = tour_cost(cand, dist)
                if c < best_cost - 1e-12:
                    best = cand
                    best_cost = c
                    improved = True
                    break
            if improved:
                break
    return best


def main() -> None:
    dist = [
        [0, 1, 8, 8, 1],
        [1, 0, 1, 8, 8],
        [8, 1, 0, 1, 8],
        [8, 8, 1, 0, 1],
        [1, 8, 8, 1, 0],
    ]
    bad = [0, 2, 4, 1, 3]
    improved = node_interchange(bad, dist)
    assert sorted(improved) == list(range(5))  # permutation preserved
    assert tour_cost(improved, dist) <= tour_cost(bad, dist)  # never worse

    # single swap fixes an obviously misplaced pair
    almost = [0, 1, 2, 4, 3]
    fixed = node_interchange(almost, dist)
    assert sorted(fixed) == list(range(5))
    assert tour_cost(fixed, dist) <= tour_cost(almost, dist)

    # degenerate cases
    assert node_interchange([], [[0]]) == []
    assert node_interchange([0], [[0]]) == [0]

    # optimal tour is a fixpoint (nothing to improve)
    opt = node_interchange(improved, dist)
    assert tour_cost(opt, dist) == tour_cost(improved, dist)

    assert stdlib_only()
    print('tsp-node-interchange.v1 OK')


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
