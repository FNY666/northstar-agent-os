"""Lin-Kernighan-style variable k-opt TSP improvement (TSP-013), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-lin-kernighan.v1"


def tour_length(dist: list[list[float]], tour: list[int]) -> float:
    n = len(tour)
    return sum(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))


def _two_opt(tour: list[int], i: int, j: int) -> list[int]:
    return tour[:i] + tour[i : j + 1][::-1] + tour[j + 1 :]


def lin_kernighan_tsp(dist: list[list[float]]) -> list[int]:
    """Mock Lin-Kernighan: nearest-neighbor start, then iterated improving
    k-swaps (2-opt and 3-opt reversals) until a local optimum is reached."""
    n = len(dist)
    if n == 0:
        return []
    if n == 1:
        return [0]
    tour = [0]
    unvisited = set(range(1, n))
    while unvisited:
        last = tour[-1]
        tour.append(min(unvisited, key=lambda j: (dist[last][j], j)))
        unvisited.discard(tour[-1])
    cur_len = tour_length(dist, tour)
    improved = True
    while improved:
        improved = False
        for i in range(n):
            for j in range(i + 2, n + (1 if i > 0 else 0)):
                if i == 0 and j == n - 1:
                    continue
                cand = _two_opt(tour, i, j)
                cand_len = tour_length(dist, cand)
                if cand_len < cur_len:
                    tour, cur_len = cand, cand_len
                    improved = True
        if improved:
            continue
        for i in range(n):
            for j in range(i + 2, n):
                for k in range(j + 2, n):
                    cand = tour[:i] + tour[i : j + 1][::-1] + tour[j + 1 : k + 1][::-1] + tour[k + 1 :]
                    cand_len = tour_length(dist, cand)
                    if cand_len < cur_len:
                        tour, cur_len = cand, cand_len
                        improved = True
                        break
                if improved:
                    break
            if improved:
                break
    return tour


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour = lin_kernighan_tsp(dist)
    assert sorted(tour) == [0, 1, 2, 3], "valid tour must visit each city exactly once"
    assert tour_length(dist, tour) == 80, f"expected optimum 80, got {tour_length(dist, tour)}"
    assert lin_kernighan_tsp([]) == []
    assert lin_kernighan_tsp([[0]]) == [0]
    assert tour_length(dist, tour) == sum(
        dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour))
    )
    five = [
        [0, 2, 9, 10, 7],
        [2, 0, 6, 4, 3],
        [9, 6, 0, 8, 5],
        [10, 4, 8, 0, 6],
        [7, 3, 5, 6, 0],
    ]
    t5 = lin_kernighan_tsp(five)
    assert sorted(t5) == [0, 1, 2, 3, 4]
    assert tour_length(five, t5) == 26, f"expected 26, got {tour_length(five, t5)}"
    assert stdlib_only()
    print("tsp-lin-kernighan.v1 OK")


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
