"""graph_10: Kosaraju's strongly connected components. Standard library only.

GRAPH_10_VERSION = graph-10.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Set

GRAPH_10_VERSION = "graph-10.v1"


def kosaraju_scc(graph: Dict[Hashable, List[Hashable]]) -> List[List[Hashable]]:
    """Kosaraju's two-pass SCC."""
    nodes: Set[Hashable] = set(graph)
    for nbrs in graph.values():
        nodes.update(nbrs)

    visited: Set[Hashable] = set()
    finish: List[Hashable] = []

    def dfs1(u: Hashable) -> None:
        visited.add(u)
        for v in graph.get(u, []):
            if v not in visited:
                dfs1(v)
        finish.append(u)

    for u in nodes:
        if u not in visited:
            dfs1(u)

    rev: Dict[Hashable, List[Hashable]] = {u: [] for u in nodes}
    for u in graph:
        for v in graph[u]:
            rev[v].append(u)

    visited.clear()
    comps: List[List[Hashable]] = []

    def dfs2(u: Hashable, comp: List[Hashable]) -> None:
        visited.add(u)
        comp.append(u)
        for v in rev[u]:
            if v not in visited:
                dfs2(v, comp)

    for u in reversed(finish):
        if u not in visited:
            comp: List[Hashable] = []
            dfs2(u, comp)
            comps.append(comp)
    return comps


def is_strongly_connected(graph: Dict[Hashable, List[Hashable]]) -> bool:
    """True iff the whole graph is one SCC."""
    nodes = set(graph)
    for nbrs in graph.values():
        nodes.update(nbrs)
    if not nodes:
        return True
    comps = kosaraju_scc(graph)
    return len(comps) == 1 and set(comps[0]) == nodes


def test_kosaraju_two_components():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["d"], "d": ["c"], "e": []}
    comps = sorted(tuple(sorted(c)) for c in kosaraju_scc(g))
    assert comps == [("a", "b"), ("c", "d"), ("e",)]


def test_kosaraju_strongly_connected():
    g = {"a": ["b"], "b": ["c"], "c": ["a"]}
    assert is_strongly_connected(g) is True


def test_kosaraju_not_strongly_connected():
    g = {"a": ["b"], "b": []}
    assert is_strongly_connected(g) is False


def test_kosaraju_agrees_with_tarjan_shape():
    g = {"a": ["b"], "b": ["c"], "c": ["a", "d"], "d": []}
    comps = sorted(tuple(sorted(c)) for c in kosaraju_scc(g))
    assert comps == [("a", "b", "c"), ("d",)]


def test_kosaraju_empty():
    assert kosaraju_scc({}) == []
    assert is_strongly_connected({}) is True


def main() -> None:
    test_kosaraju_two_components()
    test_kosaraju_strongly_connected()
    test_kosaraju_not_strongly_connected()
    test_kosaraju_agrees_with_tarjan_shape()
    test_kosaraju_empty()
    print("graph_10 (Kosaraju) OK")


if __name__ == "__main__":
    main()
