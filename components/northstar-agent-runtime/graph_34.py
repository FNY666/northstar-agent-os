"""graph_34: Undirected cycle detection via Union-Find. Standard library only.

GRAPH_34_VERSION = graph-34.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Tuple

GRAPH_34_VERSION = "graph-34.v1"


def _edges(graph: Dict[Hashable, List[Hashable]]) -> List[Tuple[Hashable, Hashable]]:
    seen = set()
    out = []
    for u, nbrs in graph.items():
        for v in nbrs:
            key = (repr(u), repr(v))
            rkey = (repr(v), repr(u))
            if key not in seen and rkey not in seen:
                seen.add(key)
                out.append((u, v))
    return out


def has_undirected_cycle(graph: Dict[Hashable, List[Hashable]]) -> bool:
    """Union-Find cycle detection; self-loops count as cycles."""
    parent: Dict[Hashable, Hashable] = {}

    def find(x: Hashable) -> Hashable:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for u, v in _edges(graph):
        if u == v:
            return True
        ru, rv = find(u), find(v)
        if ru == rv:
            return True
        parent[rv] = ru
    return False


def test_undirected_cycle_triangle():
    g = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    assert has_undirected_cycle(g) is True


def test_undirected_cycle_tree():
    g = {"a": ["b", "c"], "b": ["a"], "c": ["a"]}
    assert has_undirected_cycle(g) is False


def test_undirected_cycle_self_loop():
    assert has_undirected_cycle({"a": ["a"]}) is True


def test_undirected_cycle_disconnected():
    g = {"a": ["b"], "b": ["a"], "x": ["y", "z"], "y": ["x", "z"], "z": ["x", "y"]}
    assert has_undirected_cycle(g) is True


def test_undirected_cycle_empty():
    assert has_undirected_cycle({}) is False


def main() -> None:
    test_undirected_cycle_triangle()
    test_undirected_cycle_tree()
    test_undirected_cycle_self_loop()
    test_undirected_cycle_disconnected()
    test_undirected_cycle_empty()
    print("graph_34 (undirected cycle) OK")


if __name__ == "__main__":
    main()
