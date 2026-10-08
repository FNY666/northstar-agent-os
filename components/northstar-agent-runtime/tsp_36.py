"""Sweep algorithm (sort by polar angle, mock) (TSP-036), Simulated."""
from __future__ import annotations
import ast
import math

VERSION = "tsp-sweep.v1"


def sweep(pts: list[tuple[float, float]]) -> list[int]:
    """Sort nodes by polar angle around the centroid (mock sweep heuristic)."""
    if len(pts) <= 1:
        return list(range(len(pts)))
    cx = sum(x for x, _ in pts) / len(pts)
    cy = sum(y for _, y in pts) / len(pts)
    order = sorted(range(len(pts)),
                   key=lambda i: math.atan2(pts[i][1] - cy, pts[i][0] - cx))
    return order


def main() -> None:
    # points on a circle in scrambled order: sweep recovers circular order
    pts = [(math.cos(a), math.sin(a)) for a in (0.0, 2.1, 4.2, 1.05, 3.15, 5.25)]
    tour = sweep(pts)
    assert sorted(tour) == list(range(6))  # visits all nodes
    # angles must be non-decreasing (the sweep order property)
    cx = sum(x for x, _ in pts) / 6
    cy = sum(y for _, y in pts) / 6
    angs = [math.atan2(pts[i][1] - cy, pts[i][0] - cx) for i in tour]
    assert all(angs[i] <= angs[i + 1] for i in range(len(angs) - 1))

    # degenerate cases
    assert sweep([]) == []
    assert sweep([(1.0, 2.0)]) == [0]
    assert sorted(sweep([(0.0, 0.0), (1.0, 0.0)])) == [0, 1]  # permutation, order by angle

    # triangle: still a valid permutation
    tri = sweep([(0.0, 0.0), (2.0, 0.0), (1.0, 3.0)])
    assert sorted(tri) == [0, 1, 2]

    assert stdlib_only()
    print('tsp-sweep.v1 OK')


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
