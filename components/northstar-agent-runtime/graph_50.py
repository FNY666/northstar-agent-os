"""graph_50: Tree centers via leaf peeling. Standard library only.

GRAPH_50_VERSION = graph-50.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List

GRAPH_50_VERSION = "graph-50.v1"


def tree_centers(graph: Dict[Hashable, List[Hashable]]) -> List[Hashable]:
    """Center(s) of a tree: 1 or 2 nodes minimizing eccentricity."""
    nodes = list(graph)
    if not nodes:
        return []
    if len(nodes) == 1:
        return nodes
    degree = {u: len(graph.get(u, [])) for u in nodes}
    leaves: deque = deque([u for u in nodes if degree[u] <= 1])
    remaining = len(nodes)
    while remaining > 2:
        for _ in range(len(leaves)):
            u = leaves.popleft()
            remaining -= 1
            for v in graph.get(u, []):
                degree[v] -= 1
                if degree[v] == 1:
                    leaves.append(v)
    return list(leaves)


def test_centers_path_odd():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    assert tree_centers(g) == ["b"]


def test_centers_path_even():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c"]}
    assert sorted(tree_centers(g)) == ["b", "c"]


def test_centers_star():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    assert tree_centers(g) == ["c"]


def test_centers_single():
    assert tree_centers({"a": []}) == ["a"]


def test_centers_empty():
    assert tree_centers({}) == []


def main() -> None:
    test_centers_path_odd()
    test_centers_path_even()
    test_centers_star()
    test_centers_single()
    test_centers_empty()
    print("graph_50 (tree centers) OK")


if __name__ == "__main__":
    main()
