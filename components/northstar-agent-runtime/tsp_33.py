"""Edge-crossing elimination for euclidean tours (uncross until no crossings) (TSP-033), Simulated."""
from __future__ import annotations
import ast
import math

VERSION = "tsp-uncross.v1"


def _orient(a, b, c) -> float:
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def segments_cross(p1, p2, p3, p4) -> bool:
    """True if segments p1-p2 and p3-p4 cross at an interior point."""
    d1 = _orient(p3, p4, p1)
    d2 = _orient(p3, p4, p2)
    d3 = _orient(p1, p2, p3)
    d4 = _orient(p1, p2, p4)
    if ((d1 > 0 and d2 < 0) or (d1 < 0 and d2 > 0)) and \
       ((d3 > 0 and d4 < 0) or (d3 < 0 and d4 > 0)):
        return True
    return False


def count_crossings(tour: list[int], pts: list[tuple[float, float]]) -> int:
    n = len(tour)
    count = 0
    for i in range(n):
        a, b = pts[tour[i]], pts[tour[(i + 1) % n]]
        for j in range(i + 1, n):
            c, d = pts[tour[j]], pts[tour[(j + 1) % n]]
            if len({tour[i], tour[(i + 1) % n], tour[j], tour[(j + 1) % n]}) < 4:
                continue  # shared endpoint, not a crossing
            if segments_cross(a, b, c, d):
                count += 1
    return count


def uncross(tour: list[int], pts: list[tuple[float, float]]) -> list[int]:
    """Repeatedly 2-opt any crossing pair until no crossings remain."""
    if len(tour) < 4:
        return list(tour)
    best = list(tour)
    n = len(best)
    improved = True
    while improved:
        improved = False
        for i in range(n):
            for j in range(i + 1, n):
                a, b = best[i], best[(i + 1) % n]
                c, d = best[j], best[(j + 1) % n]
                if len({a, b, c, d}) < 4:
                    continue
                if segments_cross(pts[a], pts[b], pts[c], pts[d]):
                    # 2-opt: reverse the path between the crossing edges
                    new = best[:i + 1] + best[i + 1:j + 1][::-1] + best[j + 1:]
                    best = new
                    improved = True
                    break
            if improved:
                break
    return best


def main() -> None:
    pts = [(0.0, 0.0), (2.0, 0.0), (2.0, 2.0), (0.0, 2.0), (1.0, 1.0), (3.0, 1.0)]
    crossed = [0, 2, 1, 3, 5, 4]  # deliberately crossing tour
    fixed = uncross(crossed, pts)
    assert sorted(fixed) == list(range(6))  # permutation preserved
    assert count_crossings(fixed, pts) == 0  # no crossings left
    # uncrossing strictly reduces euclidean length
    def length(t):
        return sum(math.dist(pts[t[i]], pts[t[(i + 1) % len(t)]]) for i in range(len(t)))
    assert length(fixed) < length(crossed)

    # degenerate cases: empty / tiny tours unchanged
    assert uncross([], pts) == []
    assert uncross([0], pts) == [0]
    assert uncross([0, 1], [(0.0, 0.0), (1.0, 1.0)]) == [0, 1]
    assert uncross([0, 1, 2], [(0.0, 0.0), (1.0, 0.0), (0.0, 1.0)]) == [0, 1, 2]

    # a clean triangle tour is a fixpoint
    clean = [0, 1, 2, 3]
    sq = [(0.0, 0.0), (2.0, 0.0), (2.0, 2.0), (0.0, 2.0)]
    assert uncross(clean, sq) == clean

    assert stdlib_only()
    print('tsp-uncross.v1 OK')


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
