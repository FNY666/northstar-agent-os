"""TSP path variant (open tour, exact via Held-Karp without return edge) (TSP-040), Simulated."""
from __future__ import annotations
import ast
import itertools

VERSION = "tsp-path.v1"


def held_karp_path(dist: list[list[float]], start: int = 0) -> list[int]:
    """Exact shortest open path visiting every node once, starting at `start`
    (no return to start). DP over subsets: dp[mask][last] = min cost."""
    n = len(dist)
    if n == 0:
        return []
    if n == 1:
        return [start]
    INF = float("inf")
    dp = [[INF] * n for _ in range(1 << n)]
    parent = [[-1] * n for _ in range(1 << n)]
    dp[1 << start][start] = 0.0
    for mask in range(1 << n):
        for last in range(n):
            if dp[mask][last] == INF:
                continue
            for nxt in range(n):
                if mask & (1 << nxt):
                    continue
                nmask = mask | (1 << nxt)
                c = dp[mask][last] + dist[last][nxt]
                if c < dp[nmask][nxt]:
                    dp[nmask][nxt] = c
                    parent[nmask][nxt] = last
    full = (1 << n) - 1
    last = min(range(n), key=lambda v: dp[full][v])
    path = [last]
    mask = full
    while mask != (1 << start):
        prev = parent[mask][last]
        path.append(prev)
        mask ^= (1 << last)
        last = prev
    return path[::-1]


def path_cost(path: list[int], dist: list[list[float]]) -> float:
    return sum(dist[path[i]][path[i + 1]] for i in range(len(path) - 1))


def brute_path(dist: list[list[float]], start: int = 0) -> tuple[list[int], float]:
    best, best_c = None, float("inf")
    others = [i for i in range(len(dist)) if i != start]
    for perm in itertools.permutations(others):
        p = [start] + list(perm)
        c = path_cost(p, dist)
        if c < best_c:
            best, best_c = p, c
    return best, best_c


def main() -> None:
    dist = [
        [0, 1, 8, 8, 1],
        [1, 0, 1, 8, 8],
        [8, 1, 0, 1, 8],
        [8, 8, 1, 0, 1],
        [1, 8, 8, 1, 0],
    ]
    path = held_karp_path(dist, start=0)
    assert sorted(path) == list(range(5))  # visits every node exactly once
    assert path[0] == 0  # starts at the requested start
    # matches brute force exactly
    bp, bc = brute_path(dist, start=0)
    assert path_cost(path, dist) == bc  # optimal, no return edge
    # open path is strictly cheaper than the best closed tour here
    assert bc == 4

    # degenerate cases
    assert held_karp_path([[0]], start=0) == [0]
    assert held_karp_path([], start=0) == []

    # two nodes: just the direct edge
    d2 = [[0, 5], [5, 0]]
    assert held_karp_path(d2, start=0) == [0, 1]
    assert path_cost([0, 1], d2) == 5

    # asymmetric line: start 0, should walk straight up the line
    n = 4
    dl = [[abs(i - j) if i <= j else abs(i - j) * 10 for j in range(n)] for i in range(n)]
    pl = held_karp_path(dl, start=0)
    assert pl == [0, 1, 2, 3]

    assert stdlib_only()
    print('tsp-path.v1 OK')


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
