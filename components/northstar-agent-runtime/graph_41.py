"""graph_41: Greedy graph coloring (largest-degree-first). Standard library only.

GRAPH_41_VERSION = graph-41.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List

GRAPH_41_VERSION = "graph-41.v1"


def greedy_coloring(graph: Dict[Hashable, List[Hashable]]) -> Dict[Hashable, int]:
    """Color assignment; adjacent nodes differ. Uses degeneracy-ish ordering."""
    order = sorted(graph, key=lambda u: len(graph.get(u, [])), reverse=True)
    color: Dict[Hashable, int] = {}
    for u in order:
        used = {color[v] for v in graph.get(u, []) if v in color}
        c = 0
        while c in used:
            c += 1
        color[u] = c
    return color


def is_valid_coloring(graph: Dict[Hashable, List[Hashable]], color: Dict[Hashable, int]) -> bool:
    return all(color[u] != color[v] for u in graph for v in graph[u])


def test_coloring_bipartite_two_colors():
    g = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["a", "c"]}
    c = greedy_coloring(g)
    assert is_valid_coloring(g, c) and max(c.values()) <= 1


def test_coloring_triangle_three():
    g = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    c = greedy_coloring(g)
    assert is_valid_coloring(g, c) and len(set(c.values())) == 3


def test_coloring_bound():
    # greedy uses at most max_degree + 1 colors
    g = {"a": ["b", "c", "d"], "b": ["a"], "c": ["a"], "d": ["a"]}
    c = greedy_coloring(g)
    assert is_valid_coloring(g, c) and max(c.values()) + 1 <= 4


def test_coloring_empty():
    assert greedy_coloring({}) == {}


def test_coloring_path():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c"]}
    c = greedy_coloring(g)
    assert is_valid_coloring(g, c) and max(c.values()) <= 1


def main() -> None:
    test_coloring_bipartite_two_colors()
    test_coloring_triangle_three()
    test_coloring_bound()
    test_coloring_empty()
    test_coloring_path()
    print("graph_41 (greedy coloring) OK")


if __name__ == "__main__":
    main()
