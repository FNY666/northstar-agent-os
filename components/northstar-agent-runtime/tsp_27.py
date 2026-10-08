"""Vehicle routing split via the Clarke-Wright savings heuristic (TSP-027), Simulated."""
from __future__ import annotations
import ast
import heapq

VERSION = "tsp-vrp-savings.v1"


def clarke_wright(dist, demands, capacity):
    """Clarke-Wright savings heuristic. dist is (n+1)x(n+1) with depot 0,
    demands[i] is customer i+1's demand. Returns routes as [0, ..., 0] lists."""
    n = len(demands)
    if n == 0:
        return []
    routes = {i: [i] for i in range(1, n + 1)}
    load = {i: demands[i - 1] for i in range(1, n + 1)}
    owner = {i: i for i in range(1, n + 1)}
    savings = []
    for i in range(1, n + 1):
        for j in range(i + 1, n + 1):
            s = dist[0][i] + dist[0][j] - dist[i][j]
            savings.append((-s, i, j))
    heapq.heapify(savings)
    while savings:
        _, i, j = heapq.heappop(savings)
        ri, rj = owner[i], owner[j]
        if ri == rj:
            continue
        if load[ri] + load[rj] > capacity:
            continue
        r1, r2 = routes[ri], routes[rj]
        merged = None
        if r1[-1] == i and r2[0] == j:
            merged = r1 + r2
        elif r1[0] == i and r2[-1] == j:
            merged = r2 + r1
        elif r1[-1] == i and r2[-1] == j:
            merged = r1 + r2[::-1]
        elif r1[0] == i and r2[0] == j:
            merged = r1[::-1] + r2
        if merged is None:
            continue
        routes[ri] = merged
        load[ri] += load[rj]
        for c in r2:
            owner[c] = ri
        del routes[rj]
        del load[rj]
    return [[0] + r + [0] for r in routes.values()]


def main() -> None:
    # small instance: 3 customers on a line, demands 2 each, capacity 4
    n = 3
    dist = [[abs(i - j) for j in range(n + 1)] for i in range(n + 1)]
    routes = clarke_wright(dist, [2, 2, 2], 4)
    # savings order merges 2-3 first; customer 1 cannot join (load 6 > 4)
    assert len(routes) == 2
    covered = sorted(c for r in routes for c in r[1:-1])
    assert covered == [1, 2, 3]
    # degenerate case: no customers
    assert clarke_wright(dist, [], 4) == []
    # correctness property: capacity respected, each customer exactly once
    for r in routes:
        assert r[0] == 0 and r[-1] == 0
        assert sum([2, 2, 2][c - 1] for c in r[1:-1]) <= 4
    # single vehicle fits everything -> one route
    one = clarke_wright(dist, [2, 2, 2], 10)
    assert len(one) == 1 and sorted(one[0][1:-1]) == [1, 2, 3]
    assert stdlib_only()
    print('tsp-vrp-savings.v1 OK')


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
