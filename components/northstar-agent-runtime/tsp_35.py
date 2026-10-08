"""Cluster-first route-second (k-means-ish clustering mock + per-cluster NN) (TSP-035), Simulated."""
from __future__ import annotations
import ast
import math

VERSION = "tsp-cluster-first.v1"


def _dist(a, b) -> float:
    return math.dist(a, b)


def cluster_first(pts: list[tuple[float, float]], k: int, seed: int = 0) -> list[list[int]]:
    """Mock k-means: initialize centroids spread over the point set, then iterate
    assignment + centroid recompute until stable (capped iterations)."""
    n = len(pts)
    if n == 0 or k <= 0:
        return []
    k = min(k, n)
    centroids = [pts[(seed + i * max(1, n // k)) % n] for i in range(k)]
    assign = [-1] * n
    for _ in range(50):
        changed = False
        for i, p in enumerate(pts):
            c = min(range(k), key=lambda j: _dist(p, centroids[j]))
            if assign[i] != c:
                assign[i] = c
                changed = True
        new_centroids = []
        for j in range(k):
            members = [pts[i] for i in range(n) if assign[i] == j]
            if members:
                new_centroids.append((sum(x for x, _ in members) / len(members),
                                      sum(y for _, y in members) / len(members)))
            else:
                new_centroids.append(centroids[j])
        centroids = new_centroids
        if not changed:
            break
    clusters: list[list[int]] = [[] for _ in range(k)]
    for i, c in enumerate(assign):
        clusters[c].append(i)
    return [c for c in clusters if c]


def _nearest_neighbor(nodes: list[int], pts: list[tuple[float, float]]) -> list[int]:
    if not nodes:
        return []
    unvisited = set(nodes)
    cur = nodes[0]
    tour = [cur]
    unvisited.discard(cur)
    while unvisited:
        nxt = min(unvisited, key=lambda v: _dist(pts[cur], pts[v]))
        tour.append(nxt)
        unvisited.discard(nxt)
        cur = nxt
    return tour


def cluster_first_route_second(pts: list[tuple[float, float]], k: int) -> list[int]:
    clusters = cluster_first(pts, k)
    tour: list[int] = []
    for c in clusters:
        tour += _nearest_neighbor(c, pts)
    return tour


def main() -> None:
    # two well-separated point groups
    pts = [(0.0, 0.0), (0.5, 0.2), (0.1, 0.6),
           (10.0, 10.0), (10.4, 10.1), (9.9, 10.5)]
    clusters = cluster_first(pts, 2)
    assert len(clusters) == 2  # two clusters found
    assert sorted(i for c in clusters for i in c) == list(range(6))  # disjoint cover
    # clusters recover the true groups
    assert set(clusters[0]) == {0, 1, 2} or set(clusters[0]) == {3, 4, 5}

    tour = cluster_first_route_second(pts, 2)
    assert sorted(tour) == list(range(6))  # full route visits everyone

    # degenerate cases
    assert cluster_first([], 3) == []
    assert cluster_first_route_second([], 3) == []
    single = cluster_first_route_second([(1.0, 2.0)], 4)
    assert single == [0]

    # k larger than n collapses gracefully
    many = cluster_first_route_second(pts[:3], 10)
    assert sorted(many) == [0, 1, 2]

    assert stdlib_only()
    print('tsp-cluster-first.v1 OK')


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
