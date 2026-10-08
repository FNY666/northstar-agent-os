"""graph_01: Breadth-first search (BFS). Standard library only.

GRAPH_01_VERSION = graph-01.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List, Optional

GRAPH_01_VERSION = "graph-01.v1"


def bfs_order(graph: Dict[Hashable, List[Hashable]], start: Hashable) -> List[Hashable]:
    """Nodes in BFS visit order."""
    seen = {start}
    order: List[Hashable] = []
    q: deque = deque([start])
    while q:
        u = q.popleft()
        order.append(u)
        for v in graph.get(u, []):
            if v not in seen:
                seen.add(v)
                q.append(v)
    return order


def bfs_distances(graph: Dict[Hashable, List[Hashable]], start: Hashable) -> Dict[Hashable, int]:
    """Unweighted shortest-path distances from start."""
    dist = {start: 0}
    q: deque = deque([start])
    while q:
        u = q.popleft()
        for v in graph.get(u, []):
            if v not in dist:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist


def bfs_path(
    graph: Dict[Hashable, List[Hashable]], start: Hashable, goal: Hashable
) -> Optional[List[Hashable]]:
    """Shortest path (fewest edges) from start to goal, or None."""
    if start == goal:
        return [start]
    prev: Dict[Hashable, Optional[Hashable]] = {start: None}
    q: deque = deque([start])
    while q:
        u = q.popleft()
        for v in graph.get(u, []):
            if v not in prev:
                prev[v] = u
                if v == goal:
                    path = [v]
                    while prev[path[-1]] is not None:
                        path.append(prev[path[-1]])  # type: ignore[arg-type]
                    return path[::-1]
                q.append(v)
    return None


def test_bfs_order_simple():
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    assert bfs_order(g, "a") == ["a", "b", "c", "d"]


def test_bfs_distances():
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    assert bfs_distances(g, "a") == {"a": 0, "b": 1, "c": 1, "d": 2}


def test_bfs_path_found():
    g = {"a": ["b", "c"], "b": ["d"], "c": [], "d": []}
    assert bfs_path(g, "a", "d") == ["a", "b", "d"]


def test_bfs_path_missing():
    g = {"a": ["b"], "b": [], "c": []}
    assert bfs_path(g, "a", "c") is None


def test_bfs_disconnected():
    g = {"a": ["b"], "b": [], "c": ["d"], "d": []}
    assert bfs_order(g, "c") == ["c", "d"]
    assert "a" not in bfs_distances(g, "c")


def main() -> None:
    test_bfs_order_simple()
    test_bfs_distances()
    test_bfs_path_found()
    test_bfs_path_missing()
    test_bfs_disconnected()
    print("graph_01 (BFS) OK")


if __name__ == "__main__":
    main()
