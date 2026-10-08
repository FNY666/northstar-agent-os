"""Farthest-first traversal ordering (mock TSP seed) (TSP-047), Simulated."""
from __future__ import annotations
import ast
import math

VERSION = "tsp-farthest-first.v1"

def dist2(p: tuple[float, float], q: tuple[float, float]) -> float:
    return math.hypot(p[0] - q[0], p[1] - q[1])

def farthest_first(points: list[tuple[float, float]]) -> list[int]:
    """Greedy farthest-point ordering as a TSP seed."""
    n = len(points)
    if n == 0:
        return []
    order = [0]
    chosen = {0}
    while len(order) < n:
        def score(i: int) -> float:
            return min(dist2(points[i], points[j]) for j in order)
        nxt = max((i for i in range(n) if i not in chosen), key=score)
        order.append(nxt)
        chosen.add(nxt)
    return order

def main() -> None:
    pts = [(0, 0), (1, 0), (0, 1), (1, 1), (2, 2), (3, 0)]
    o = farthest_first(pts)
    assert sorted(o) == list(range(6)), o
    assert o[0] == 0
    # second pick should be far from (0,0): (2,2) or (3,0)
    assert o[1] in (4, 5), o
    assert farthest_first([]) == []
    assert farthest_first([(5, 5)]) == [0]
    assert stdlib_only()
    print('tsp-farthest-first.v1 OK')

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
