"""graph_20: Hungarian algorithm for assignment (O(n^3)). Standard library only.

GRAPH_20_VERSION = graph-20.v1
"""
from __future__ import annotations

from typing import List, Tuple

GRAPH_20_VERSION = "graph-20.v1"


def hungarian(cost: List[List[float]]) -> Tuple[List[int], float]:
    """Min-cost assignment for n x n matrix. Returns (assign, total_cost).

    assign[i] = column assigned to row i.
    """
    n = len(cost)
    if n == 0:
        return [], 0.0
    if any(len(row) != n for row in cost):
        raise ValueError("cost matrix must be square")
    u = [0.0] * (n + 1)
    v = [0.0] * (n + 1)
    p = [0] * (n + 1)
    way = [0] * (n + 1)
    for i in range(1, n + 1):
        p[0] = i
        j0 = 0
        minv = [float("inf")] * (n + 1)
        used = [False] * (n + 1)
        while True:
            used[j0] = True
            i0 = p[j0]
            delta = float("inf")
            j1 = 0
            for j in range(1, n + 1):
                if not used[j]:
                    cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j] = cur
                        way[j] = j0
                    if minv[j] < delta:
                        delta = minv[j]
                        j1 = j
            for j in range(n + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while j0:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
    assign = [0] * n
    for j in range(1, n + 1):
        if p[j]:
            assign[p[j] - 1] = j - 1
    total = sum(cost[i][assign[i]] for i in range(n))
    return assign, total


def test_hungarian_basic():
    cost = [[4, 1, 3], [2, 0, 5], [3, 2, 2]]
    assign, total = hungarian(cost)
    assert total == 5.0  # (0,1),(1,0),(2,2)
    assert sorted(assign) == [0, 1, 2]


def test_hungarian_identity():
    cost = [[1, 9, 9], [9, 1, 9], [9, 9, 1]]
    assign, total = hungarian(cost)
    assert total == 3.0 and assign == [0, 1, 2]


def test_hungarian_single():
    assert hungarian([[42]]) == ([0], 42.0)


def test_hungarian_rectangular_rejected():
    try:
        hungarian([[1, 2, 3], [4, 5, 6]])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_hungarian_empty():
    assert hungarian([]) == ([], 0.0)


def main() -> None:
    test_hungarian_basic()
    test_hungarian_identity()
    test_hungarian_single()
    test_hungarian_rectangular_rejected()
    test_hungarian_empty()
    print("graph_20 (Hungarian) OK")


if __name__ == "__main__":
    main()
