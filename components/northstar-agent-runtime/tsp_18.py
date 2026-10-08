"""Space-filling-curve TSP heuristic (TSP-018), Simulated."""
from __future__ import annotations
import ast
import math

VERSION = "tsp-space-filling.v1"


def space_filling_tsp(points: list[tuple[float, float]]) -> list[int]:
    """Hilbert-ish space-filling mock: order cities by polar angle around the
    centroid, tie-broken by radius. Produces a decent tour for clustered points."""
    n = len(points)
    if n == 0:
        return []
    if n == 1:
        return [0]
    cx = sum(p[0] for p in points) / n
    cy = sum(p[1] for p in points) / n
    keyed = []
    for i, (x, y) in enumerate(points):
        dx, dy = x - cx, y - cy
        keyed.append((math.atan2(dy, dx), math.hypot(dx, dy), i))
    keyed.sort()
    return [i for _, _, i in keyed]


def tour_length(points: list[tuple[float, float]], tour: list[int]) -> float:
    n = len(tour)
    total = 0.0
    for k in range(n):
        a, b = points[tour[k]], points[tour[(k + 1) % n]]
        total += math.hypot(a[0] - b[0], a[1] - b[1])
    return total


def main() -> None:
    pts = [(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)]
    tour = space_filling_tsp(pts)
    assert sorted(tour) == [0, 1, 2, 3], "valid tour must visit each city exactly once"
    assert tour_length(pts, tour) == 4.0, f"unit square optimum is 4, got {tour_length(pts, tour)}"
    assert space_filling_tsp([]) == []
    assert space_filling_tsp([(5.0, 5.0)]) == [0]
    assert tour_length(pts, tour) == sum(
        math.hypot(pts[tour[i]][0] - pts[tour[(i + 1) % 4]][0],
                   pts[tour[i]][1] - pts[tour[(i + 1) % 4]][1])
        for i in range(4)
    )
    circle = [(math.cos(2 * math.pi * k / 6), math.sin(2 * math.pi * k / 6)) for k in range(6)]
    tc = space_filling_tsp(circle)
    assert tour_length(circle, tc) == 6.0, "unit hexagon perimeter must be 6"
    assert stdlib_only()
    print("tsp-space-filling.v1 OK")


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
