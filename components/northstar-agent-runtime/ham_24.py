"""TSP exact brute force small n (HAM-024), Real."""
from __future__ import annotations
import ast

VERSION = "ham-24.v1"

def tsp_bruteforce(n, dist):
    import itertools
    if n == 0:
        return ([], 0)
    if n == 1:
        return ([0], 0)
    best = None
    bestc = None
    for perm in itertools.permutations(range(1, n)):
        tour = (0,) + perm
        c = sum(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))
        if bestc is None or c < bestc:
            bestc = c
            best = list(tour)
    return (best, bestc)

def main() -> None:
    dist = [[0, 10, 15, 20], [10, 0, 35, 25], [15, 35, 0, 30], [20, 25, 30, 0]]
    tour, cost = tsp_bruteforce(4, dist)
    assert sorted(tour) == [0, 1, 2, 3] and tour[0] == 0
    assert cost == 80
    assert tsp_bruteforce(1, [[0]]) == ([0], 0)
    assert tsp_bruteforce(0, []) == ([], 0)
    d2 = [[0, 5], [5, 0]]
    t2, c2 = tsp_bruteforce(2, d2)
    assert c2 == 10 and sorted(t2) == [0, 1]
    assert stdlib_only()
    print('ham-24.v1 OK')
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
