"""graph_35: Connected components of an undirected graph. Standard library only.

GRAPH_35_VERSION = graph-35.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List, Set

GRAPH_35_VERSION = "graph-35.v1"


def connected_components(graph: Dict[Hashable, List[Hashable]]) -> List[List[Hashable]]:
    """All connected components (treating edges as undirected)."""
    seen: Set[Hashable] = set()
    comps: List[List[Hashable]] = []
    for start in graph:
        if start in seen:
            continue
        comp = []
        q: deque = deque([start])
        seen.add(start)
        while q:
            u = q.popleft()
            comp.append(u)
            for v in graph.get(u, []):
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        comps.append(comp)
    return comps


def num_components(graph: Dict[Hashable, List[Hashable]]) -> int:
    return len(connected_components(graph))


def is_connected(graph: Dict[Hashable, List[Hashable]]) -> bool:
    return num_components(graph) <= 1


def test_cc_two_components():
    g = {"a": ["b"], "b": ["a"], "c": ["d"], "d": ["c"]}
    comps = sorted(sorted(c) for c in connected_components(g))
    assert comps == [["a", "b"], ["c", "d"]]


def test_cc_single():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    assert is_connected(g) is True


def test_cc_isolated():
    g = {"a": ["b"], "b": ["a"], "c": []}
    assert num_components(g) == 2


def test_cc_empty():
    assert connected_components({}) == []
    assert is_connected({}) is True


def test_cc_covers_all_nodes():
    g = {"a": ["b"], "b": ["a"], "c": ["d"], "d": ["c"], "e": []}
    comps = connected_components(g)
    assert sorted(u for c in comps for u in c) == ["a", "b", "c", "d", "e"]


def main() -> None:
    test_cc_two_components()
    test_cc_single()
    test_cc_isolated()
    test_cc_empty()
    test_cc_covers_all_nodes()
    print("graph_35 (connected components) OK")


if __name__ == "__main__":
    main()
