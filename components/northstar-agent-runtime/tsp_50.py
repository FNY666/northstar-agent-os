"""TSP instance generator (random symmetric euclidean instances, fixed seed) + verifier (TSP-050), Simulated."""
from __future__ import annotations
import ast
import math
import random

VERSION = "tsp-instance-gen.v1"

def generate(n: int, seed: int = 11, scale: float = 100.0) -> tuple[list[tuple[float, float]], list[list[float]]]:
    rng = random.Random(seed)
    pts = [(rng.uniform(0, scale), rng.uniform(0, scale)) for _ in range(n)]
    dist = [[math.hypot(p[0] - q[0], p[1] - q[1]) for q in pts] for p in pts]
    return pts, dist

def verify(pts: list[tuple[float, float]], dist: list[list[float]]) -> bool:
    n = len(pts)
    if len(dist) != n or any(len(row) != n for row in dist):
        return False
    for i in range(n):
        if dist[i][i] != 0.0:
            return False
        for j in range(n):
            if dist[i][j] < 0 or dist[i][j] != dist[j][i]:
                return False
            if abs(dist[i][j] - math.hypot(pts[i][0] - pts[j][0], pts[i][1] - pts[j][1])) > 1e-9:
                return False
    return True

def main() -> None:
    pts, dist = generate(5, seed=11)
    assert len(pts) == 5 and verify(pts, dist)
    pts2, dist2 = generate(5, seed=11)
    assert pts2 == pts and dist2 == dist  # fixed seed reproducible
    pts3, _ = generate(5, seed=12)
    assert pts3 != pts  # different seed differs
    p0, d0 = generate(0)
    assert p0 == [] and d0 == [] and verify(p0, d0)
    p1, d1 = generate(1)
    assert len(p1) == 1 and verify(p1, d1)
    assert stdlib_only()
    print('tsp-instance-gen.v1 OK')

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
