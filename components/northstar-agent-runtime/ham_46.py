"""Nearest neighbor Hamiltonian tour heuristic (HAM-046), Real."""
from __future__ import annotations
import ast

VERSION = "ham-46.v1"

def nearest_neighbor_tour(n, dist, start=0):
    unvisited = set(range(n))
    unvisited.remove(start)
    tour = [start]
    while unvisited:
        cur = tour[-1]
        nxt = min(unvisited, key=lambda v: dist[cur][v])
        tour.append(nxt)
        unvisited.remove(nxt)
    return tour

def tour_cost(n, dist, tour):
    return sum(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))

def main() -> None:
    dist = [[0, 10, 15, 20], [10, 0, 35, 25], [15, 35, 0, 30], [20, 25, 30, 0]]
    t = nearest_neighbor_tour(4, dist)
    assert sorted(t) == [0, 1, 2, 3] and t[0] == 0
    assert tour_cost(4, dist, t) == 80
    t2 = nearest_neighbor_tour(4, dist, start=2)
    assert t2[0] == 2 and sorted(t2) == [0, 1, 2, 3]
    assert nearest_neighbor_tour(1, [[0]]) == [0]
    assert tour_cost(1, [[0]], [0]) == 0
    assert stdlib_only()
    print('ham-46.v1 OK')
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
