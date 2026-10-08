"""Basic graph utilities (adjacency dict: node -> iterable).

bfs_distances, connected_components, has_path.
"""

from __future__ import annotations

from collections import deque


def _neighbors(adj, u):
    return adj.get(u, ())


def bfs_distances(adj, start) -> dict:
    """Shortest-path distances (unweighted) from start."""
    dist = {start: 0}
    queue = deque([start])
    while queue:
        u = queue.popleft()
        for v in _neighbors(adj, u):
            if v not in dist:
                dist[v] = dist[u] + 1
                queue.append(v)
    return dist


def has_path(adj, u, v) -> bool:
    return v in bfs_distances(adj, u)


def connected_components(adj) -> list:
    """Weakly connected components (treats edges as undirected)."""
    nodes = set(adj)
    for vs in adj.values():
        nodes.update(vs)
    seen: set = set()
    comps = []
    for s in nodes:
        if s in seen:
            continue
        comp = set()
        queue = deque([s])
        seen.add(s)
        while queue:
            u = queue.popleft()
            comp.add(u)
            for w in _neighbors(adj, u):
                if w not in seen:
                    seen.add(w)
                    queue.append(w)
            # reverse edges for undirected view
            for x, vs in adj.items():
                if u in vs and x not in seen:
                    seen.add(x)
                    queue.append(x)
        comps.append(comp)
    return comps


def main() -> None:
    adj = {"a": ["b", "c"], "b": ["d"], "c": [], "d": [], "e": []}
    assert bfs_distances(adj, "a") == {"a": 0, "b": 1, "c": 1, "d": 2}
    assert has_path(adj, "a", "d")
    assert not has_path(adj, "a", "e")
    comps = connected_components(adj)
    assert len(comps) == 2
    print("math_39 OK")


if __name__ == "__main__":
    main()
