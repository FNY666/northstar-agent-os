"""graph_25: Bridge-finding via DFS lowlink (Tarjan). Standard library only.

GRAPH_25_VERSION = graph-25.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Set, Tuple

GRAPH_25_VERSION = "graph-25.v1"


def find_bridges(graph: Dict[Hashable, List[Hashable]]) -> List[Tuple[Hashable, Hashable]]:
    """All bridges in an undirected graph (as sorted pairs)."""
    disc: Dict[Hashable, int] = {}
    low: Dict[Hashable, int] = {}
    bridges: Set[Tuple[Hashable, Hashable]] = set()
    timer = [0]

    def dfs(u: Hashable, parent: Hashable | None) -> None:
        disc[u] = low[u] = timer[0]
        timer[0] += 1
        for v in graph.get(u, []):
            if v == parent:
                continue
            if v not in disc:
                dfs(v, u)
                low[u] = min(low[u], low[v])
                if low[v] > disc[u]:
                    bridges.add(tuple(sorted((u, v), key=repr)))  # type: ignore[arg-type]
            else:
                low[u] = min(low[u], disc[v])

    for u in graph:
        if u not in disc:
            dfs(u, None)
    return sorted(bridges, key=repr)


def test_bridges_path():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    assert find_bridges(g) == [("a", "b"), ("b", "c")]


def test_bridges_cycle_none():
    g = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    assert find_bridges(g) == []


def test_bridges_dumbbell():
    g = {"a": ["b", "c", "d"], "b": ["a", "c"], "c": ["a", "b"],
         "d": ["a", "e", "f"], "e": ["d", "f"], "f": ["d", "e"]}
    assert find_bridges(g) == [("a", "d")]


def test_bridges_disconnected():
    g = {"a": ["b"], "b": ["a"], "c": ["d"], "d": ["c"]}
    assert find_bridges(g) == [("a", "b"), ("c", "d")]


def test_bridges_single_edge():
    assert find_bridges({"a": ["b"], "b": ["a"]}) == [("a", "b")]


def main() -> None:
    test_bridges_path()
    test_bridges_cycle_none()
    test_bridges_dumbbell()
    test_bridges_disconnected()
    test_bridges_single_edge()
    print("graph_25 (bridges) OK")


if __name__ == "__main__":
    main()
