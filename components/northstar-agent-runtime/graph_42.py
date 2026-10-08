"""graph_42: Greedy maximal independent set. Standard library only.

GRAPH_42_VERSION = graph-42.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Set

GRAPH_42_VERSION = "graph-42.v1"


def greedy_independent_set(graph: Dict[Hashable, List[Hashable]]) -> List[Hashable]:
    """Maximal (not maximum) independent set, smallest-degree-first."""
    remaining = set(graph)
    indep: List[Hashable] = []
    while remaining:
        u = min(remaining, key=lambda x: len([v for v in graph.get(x, []) if v in remaining]))
        indep.append(u)
        remaining.discard(u)
        for v in graph.get(u, []):
            remaining.discard(v)
    return indep


def is_independent(graph: Dict[Hashable, List[Hashable]], nodes: List[Hashable]) -> bool:
    s = set(nodes)
    return all(v not in s for u in nodes for v in graph.get(u, []))


def is_maximal(graph: Dict[Hashable, List[Hashable]], nodes: List[Hashable]) -> bool:
    s = set(nodes)
    for u in graph:
        if u not in s and all(v not in s for v in graph.get(u, [])):
            return False
    return True


def test_independent_path():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    s = greedy_independent_set(g)
    assert is_independent(g, s) and is_maximal(g, s)


def test_independent_complete():
    nodes = ["a", "b", "c"]
    g = {u: [v for v in nodes if v != u] for u in nodes}
    s = greedy_independent_set(g)
    assert len(s) == 1


def test_independent_empty_graph():
    g = {"a": [], "b": [], "c": []}
    s = greedy_independent_set(g)
    assert sorted(s) == ["a", "b", "c"]


def test_independent_star():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    s = greedy_independent_set(g)
    assert is_independent(g, s) and is_maximal(g, s) and len(s) == 3


def test_independent_none():
    assert greedy_independent_set({}) == []


def main() -> None:
    test_independent_path()
    test_independent_complete()
    test_independent_empty_graph()
    test_independent_star()
    test_independent_none()
    print("graph_42 (independent set) OK")


if __name__ == "__main__":
    main()
