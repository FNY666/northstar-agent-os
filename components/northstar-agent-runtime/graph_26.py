"""graph_26: Articulation points via DFS lowlink (Tarjan). Standard library only.

GRAPH_26_VERSION = graph-26.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Set

GRAPH_26_VERSION = "graph-26.v1"


def articulation_points(graph: Dict[Hashable, List[Hashable]]) -> List[Hashable]:
    """All articulation (cut) vertices of an undirected graph."""
    disc: Dict[Hashable, int] = {}
    low: Dict[Hashable, int] = {}
    aps: Set[Hashable] = set()
    timer = [0]

    def dfs(u: Hashable, parent: Hashable | None, root_children: List[int]) -> None:
        disc[u] = low[u] = timer[0]
        timer[0] += 1
        children = 0
        for v in graph.get(u, []):
            if v == parent:
                continue
            if v not in disc:
                children += 1
                dfs(v, u, root_children)
                low[u] = min(low[u], low[v])
                if parent is not None and low[v] >= disc[u]:
                    aps.add(u)
            else:
                low[u] = min(low[u], disc[v])
        if parent is None and children > 1:
            aps.add(u)

    for u in graph:
        if u not in disc:
            dfs(u, None, [])
    return sorted(aps, key=repr)


def test_ap_path():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    assert articulation_points(g) == ["b"]


def test_ap_cycle_none():
    g = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    assert articulation_points(g) == []


def test_ap_star():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    assert articulation_points(g) == ["c"]


def test_ap_dumbbell():
    g = {"a": ["b", "c", "d"], "b": ["a", "c"], "c": ["a", "b"],
         "d": ["a", "e"], "e": ["d"]}
    assert articulation_points(g) == ["a", "d"]


def test_ap_disconnected():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"], "x": ["y"], "y": ["x"]}
    assert articulation_points(g) == ["b"]


def main() -> None:
    test_ap_path()
    test_ap_cycle_none()
    test_ap_star()
    test_ap_dumbbell()
    test_ap_disconnected()
    print("graph_26 (articulation points) OK")


if __name__ == "__main__":
    main()
