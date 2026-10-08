"""Regret insertion heuristic (mock: 2-regret) (TSP-038), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-regret-insertion.v1"


def _insertion_cost(v: int, tour: list[int], dist: list[list[float]], pos: int) -> float:
    n = len(tour)
    a = tour[(pos - 1) % n]
    b = tour[pos % n]
    return dist[a][v] + dist[v][b] - dist[a][b]


def regret_insertion(dist: list[list[float]], start: int = 0) -> list[int]:
    """2-regret: repeatedly insert the unvisited city whose (2nd cheapest -
    cheapest) insertion cost is maximal, at its cheapest position."""
    n = len(dist)
    if n == 0:
        return []
    if n == 1:
        return [start]
    unvisited = set(range(n)) - {start}
    tour = [start]
    while unvisited:
        best_v, best_pos, best_regret = -1, -1, float("-inf")
        for v in unvisited:
            costs = sorted(_insertion_cost(v, tour, dist, p) for p in range(len(tour)))
            regret = (costs[1] if len(costs) > 1 else costs[0]) - costs[0]
            if regret > best_regret:
                best_regret = regret
                best_v = v
                best_pos = min(range(len(tour)), key=lambda p: _insertion_cost(v, tour, dist, p))
        tour = tour[:best_pos] + [best_v] + tour[best_pos:]
        unvisited.discard(best_v)
    # re-anchor at start (insertion positions are rotation-free)
    k = tour.index(start)
    return tour[k:] + tour[:k]


def tour_cost(tour: list[int], dist: list[list[float]]) -> float:
    if not tour:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def main() -> None:
    dist = [
        [0, 1, 8, 8, 1],
        [1, 0, 1, 8, 8],
        [8, 1, 0, 1, 8],
        [8, 8, 1, 0, 1],
        [1, 8, 8, 1, 0],
    ]
    tour = regret_insertion(dist)
    assert sorted(tour) == list(range(5))  # full tour
    assert tour[0] == 0  # anchored at start
    # optimal tour here has cost 5; 2-regret should find it
    assert tour_cost(tour, dist) == 5

    # degenerate cases
    assert regret_insertion([[0]]) == [0]
    assert regret_insertion([]) == []

    # two nodes: cost of going and returning
    d2 = [[0, 5], [5, 0]]
    t2 = regret_insertion(d2)
    assert sorted(t2) == [0, 1]
    assert tour_cost(t2, d2) == 10

    # line metric: tour should equal twice the span (2 * 12 = 24)
    n = 5
    dline = [[abs(i - j) for j in range(n)] for i in range(n)]
    tline = regret_insertion(dline)
    assert sorted(tline) == list(range(n))
    assert tour_cost(tline, dline) == 8  # 2*(4)

    assert stdlib_only()
    print('tsp-regret-insertion.v1 OK')


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
