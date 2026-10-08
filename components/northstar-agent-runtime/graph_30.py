"""graph_30: Tree diameter via two BFS/DFS passes. Standard library only.

GRAPH_30_VERSION = graph-30.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List, Tuple

GRAPH_30_VERSION = "graph-30.v1"


def _farthest(
    graph: Dict[Hashable, List[Hashable]], start: Hashable
) -> Tuple[Hashable, int, Dict[Hashable, Hashable | None]]:
    dist = {start: 0}
    prev: Dict[Hashable, Hashable | None] = {start: None}
    q: deque = deque([start])
    far = start
    while q:
        u = q.popleft()
        far = u
        for v in graph.get(u, []):
            if v not in dist:
                dist[v] = dist[u] + 1
                prev[v] = u
                q.append(v)
    return far, dist[far], prev


def tree_diameter(graph: Dict[Hashable, List[Hashable]]) -> Tuple[int, List[Hashable]]:
    """Returns (diameter_length, diameter_path). Empty graph -> (0, [])."""
    if not graph:
        return 0, []
    start = next(iter(graph))
    a, _, _ = _farthest(graph, start)
    b, length, prev = _farthest(graph, a)
    path = [b]
    while prev[path[-1]] is not None:
        path.append(prev[path[-1]])  # type: ignore[arg-type]
    return length, path[::-1]


def test_diameter_path_graph():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c"]}
    length, path = tree_diameter(g)
    assert length == 3 and path == ["a", "b", "c", "d"]


def test_diameter_star():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    length, path = tree_diameter(g)
    assert length == 2 and len(path) == 3


def test_diameter_single():
    assert tree_diameter({"a": []}) == (0, ["a"])


def test_diameter_empty():
    assert tree_diameter({}) == (0, [])


def test_diameter_binary_tree():
    g = {1: [2, 3], 2: [1, 4, 5], 3: [1, 6, 7], 4: [2], 5: [2], 6: [3], 7: [3]}
    length, path = tree_diameter(g)
    assert length == 4 and len(path) == 5


def main() -> None:
    test_diameter_path_graph()
    test_diameter_star()
    test_diameter_single()
    test_diameter_empty()
    test_diameter_binary_tree()
    print("graph_30 (tree diameter) OK")


if __name__ == "__main__":
    main()
