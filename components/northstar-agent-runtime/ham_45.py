"""Two opt Hamiltonian tour improvement (HAM-045), Real."""
from __future__ import annotations
import ast

VERSION = "ham-45.v1"

def two_opt_tour(n, dist, seed=0, max_iter=200):
    import random
    rng = random.Random(seed)
    tour = list(range(n))
    rng.shuffle(tour)
    def cost(t):
        return sum(dist[t[i]][t[(i + 1) % n]] for i in range(n))
    best = cost(tour)
    for _ in range(max_iter):
        improved = False
        for i in range(n):
            for j in range(i + 2, n):
                if i == 0 and j == n - 1:
                    continue
                cand = tour[:i + 1] + tour[i + 1:j + 1][::-1] + tour[j + 1:]
                c = cost(cand)
                if c < best:
                    tour, best = cand, c
                    improved = True
        if not improved:
            break
    return tour, best

def main() -> None:
    dist = [[0, 10, 15, 20], [10, 0, 35, 25], [15, 35, 0, 30], [20, 25, 30, 0]]
    tour, best = two_opt_tour(4, dist)
    assert sorted(tour) == [0, 1, 2, 3]
    assert best == sum(dist[tour[i]][tour[(i + 1) % 4]] for i in range(4))
    assert best <= 95
    t2, b2 = two_opt_tour(4, dist, seed=0)
    assert t2 == tour and b2 == best
    d3 = [[0, 1, 1], [1, 0, 1], [1, 1, 0]]
    t3, b3 = two_opt_tour(3, d3)
    assert b3 == 3
    assert stdlib_only()
    print('ham-45.v1 OK')
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
