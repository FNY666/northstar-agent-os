"""graph_44: Greedy dominating set (ln n approximation). Standard library only.

GRAPH_44_VERSION = graph-44.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Set

GRAPH_44_VERSION = "graph-44.v1"


def greedy_dominating_set(graph: Dict[Hashable, List[Hashable]]) -> List[Hashable]:
    """Repeatedly pick the vertex covering the most uncovered vertices."""
    uncovered = set(graph)
    dom: List[Hashable] = []
    while uncovered:
        def cover_size(u: Hashable) -> int:
            return len(({u} | set(graph.get(u, []))) & uncovered)
        u = max(graph, key=cover_size)
        dom.append(u)
        uncovered -= {u} | set(graph.get(u, []))
    return dom


def is_dominating(graph: Dict[Hashable, List[Hashable]], dom: List[Hashable]) -> bool:
    s = set(dom)
    return all(u in s or any(v in s for v in graph.get(u, [])) for u in graph)


def test_dominating_path():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    d = greedy_dominating_set(g)
    assert is_dominating(g, d) and len(d) == 1


def test_dominating_star():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    d = greedy_dominating_set(g)
    assert is_dominating(g, d) and d == ["c"]


def test_dominating_complete():
    nodes = ["a", "b", "c"]
    g = {u: [v for v in nodes if v != u] for u in nodes}
    d = greedy_dominating_set(g)
    assert len(d) == 1 and is_dominating(g, d)


def test_dominating_isolated():
    g = {"a": [], "b": []}
    d = greedy_dominating_set(g)
    assert sorted(d) == ["a", "b"]


def test_dominating_cycle():
    g = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c", "a"]}
    d = greedy_dominating_set(g)
    assert is_dominating(g, d)


def main() -> None:
    test_dominating_path()
    test_dominating_star()
    test_dominating_complete()
    test_dominating_isolated()
    test_dominating_cycle()
    print("graph_44 (dominating set) OK")


if __name__ == "__main__":
    main()
