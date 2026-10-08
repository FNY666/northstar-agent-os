"""graph_18: Bipartite check via BFS 2-coloring. Standard library only.

GRAPH_18_VERSION = graph-18.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List, Optional, Tuple

GRAPH_18_VERSION = "graph-18.v1"


def bipartite_coloring(
    graph: Dict[Hashable, List[Hashable]],
) -> Optional[Tuple[List[Hashable], List[Hashable]]]:
    """Returns (part_a, part_b) if bipartite, else None."""
    color: Dict[Hashable, int] = {}
    for start in graph:
        if start in color:
            continue
        color[start] = 0
        q: deque = deque([start])
        while q:
            u = q.popleft()
            for v in graph.get(u, []):
                if v not in color:
                    color[v] = 1 - color[u]
                    q.append(v)
                elif color[v] == color[u]:
                    return None
    part_a = [u for u, c in color.items() if c == 0]
    part_b = [u for u, c in color.items() if c == 1]
    return part_a, part_b


def is_bipartite(graph: Dict[Hashable, List[Hashable]]) -> bool:
    return bipartite_coloring(graph) is not None


def test_bipartite_square():
    g = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["a", "c"]}
    parts = bipartite_coloring(g)
    assert parts is not None
    a, b = parts
    assert sorted(a) == ["a", "c"] and sorted(b) == ["b", "d"]


def test_bipartite_triangle():
    g = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    assert is_bipartite(g) is False
    assert bipartite_coloring(g) is None


def test_bipartite_tree():
    g = {1: [2, 3], 2: [1, 4], 3: [1], 4: [2]}
    assert is_bipartite(g) is True


def test_bipartite_disconnected():
    g = {"a": ["b"], "b": ["a"], "c": ["d"], "d": ["c"], "e": []}
    assert is_bipartite(g) is True


def test_bipartite_odd_cycle_5():
    g = {0: [1, 4], 1: [0, 2], 2: [1, 3], 3: [2, 4], 4: [3, 0]}
    assert is_bipartite(g) is False


def main() -> None:
    test_bipartite_square()
    test_bipartite_triangle()
    test_bipartite_tree()
    test_bipartite_disconnected()
    test_bipartite_odd_cycle_5()
    print("graph_18 (bipartite check) OK")


if __name__ == "__main__":
    main()
