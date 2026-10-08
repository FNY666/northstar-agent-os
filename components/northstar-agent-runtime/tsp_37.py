"""Clarke-Wright savings algorithm for TSP tour (TSP-037), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-clarke-wright.v1"


def clarke_wright(dist: list[list[float]], depot: int = 0) -> list[int]:
    """Build routes by merging in descending savings order, then return the
    merged route(s) as a tour starting at the depot."""
    n = len(dist)
    if n == 0:
        return []
    if n == 1:
        return [depot]
    routes: list[list[int]] = [[i] for i in range(n) if i != depot]

    def savings(i: int, j: int) -> float:
        return dist[depot][i] + dist[depot][j] - dist[i][j]

    pairs = [(i, j) for i in range(n) if i != depot
             for j in range(i + 1, n) if j != depot]
    pairs.sort(key=lambda p: savings(*p), reverse=True)

    def find(v: int) -> list[int]:
        for r in routes:
            if v in r:
                return r
        raise KeyError(v)

    # merge any two distinct routes whose endpoints include a savings pair;
    # repeat until no merge is possible (mock keeps merging everything)
    while True:
        merged = False
        for i, j in pairs:
            ri, rj = find(i), find(j)
            if ri is rj:
                continue
            combo = None
            if ri[-1] == i and rj[0] == j:
                combo = ri + rj
            elif ri[0] == i and rj[-1] == j:
                combo = rj + ri
            elif ri[0] == i and rj[0] == j:
                combo = ri[::-1] + rj
            elif ri[-1] == i and rj[-1] == j:
                combo = ri + rj[::-1]
            else:
                continue
            routes.remove(ri)
            routes.remove(rj)
            routes.append(combo)
            merged = True
            break
        if not merged:
            break
    body: list[int] = []
    for r in routes:
        body += r
    return [depot] + body


def tour_cost(tour: list[int], dist: list[list[float]]) -> float:
    if not tour:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def main() -> None:
    dist = [
        [0, 2, 9, 10],
        [2, 0, 6, 4],
        [9, 6, 0, 8],
        [10, 4, 8, 0],
    ]
    tour = clarke_wright(dist)
    assert sorted(tour) == [0, 1, 2, 3]  # covers every node
    assert tour[0] == 0  # starts at the depot
    # never worse than the naive star: 0-1-0-2-0-3-0 collapsed = sum of 2*each
    star = 2 * (dist[0][1] + dist[0][2] + dist[0][3])
    assert tour_cost(tour, dist) <= star

    # degenerate cases
    assert clarke_wright([[0]]) == [0]
    assert clarke_wright([]) == []

    # two nodes: depot + one customer
    d2 = [[0, 5], [5, 0]]
    assert clarke_wright(d2) == [0, 1]

    # symmetric 6-node instance still yields a full valid tour
    n = 6
    d6 = [[abs(i - j) * 3 + 1 if i != j else 0 for j in range(n)] for i in range(n)]
    t6 = clarke_wright(d6)
    assert sorted(t6) == list(range(6))
    assert t6[0] == 0

    assert stdlib_only()
    print('tsp-clarke-wright.v1 OK')


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
