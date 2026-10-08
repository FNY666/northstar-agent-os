"""Stripe / strip heuristic (mock: sort by x then snake) (TSP-048), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-stripe.v1"

def stripe_tour(points: list[tuple[float, float]], strips: int = 2) -> list[int]:
    """Sort cities by x into vertical strips; snake through strips by y."""
    n = len(points)
    if n == 0:
        return []
    xs = sorted(p[0] for p in points)
    lo, hi = xs[0], xs[-1]
    width = (hi - lo) / strips if hi > lo else 1.0
    tour: list[int] = []
    for s in range(strips):
        band = [i for i, p in enumerate(points)
                if (p[0] - lo) / width >= s and ((p[0] - lo) / width < s + 1 or s == strips - 1)]
        band.sort(key=lambda i: points[i][1], reverse=(s % 2 == 1))
        tour.extend(band)
    assert sorted(tour) == list(range(n))
    return tour

def main() -> None:
    pts = [(0, 0), (0, 1), (1, 0), (1, 1), (2, 0), (2, 1)]
    t = stripe_tour(pts, strips=3)
    assert sorted(t) == list(range(6)), t
    # strip 0 (x=0): ascending y -> 0 then 1; strip 1 (x=1): descending y -> 3 then 2
    assert t[0:2] == [0, 1], t
    assert t[2:4] == [3, 2], t
    assert t[4:6] == [4, 5], t
    assert stripe_tour([]) == []
    assert stripe_tour([(7, 7)]) == [0]
    assert stdlib_only()
    print('tsp-stripe.v1 OK')

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
