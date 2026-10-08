"""graph_07: Topological sort via DFS with cycle detection. Standard library only.

GRAPH_07_VERSION = graph-07.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List

GRAPH_07_VERSION = "graph-07.v1"


class CycleError(ValueError):
    """Raised when the graph is not a DAG."""


def topo_sort_dfs(graph: Dict[Hashable, List[Hashable]]) -> List[Hashable]:
    """Topological order; raises CycleError if a cycle exists."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {u: WHITE for u in graph}
    order: List[Hashable] = []

    def visit(u: Hashable) -> None:
        color[u] = GRAY
        for v in graph.get(u, []):
            if v not in color:
                color[v] = WHITE
            if color[v] == GRAY:
                raise CycleError(f"cycle detected at {v}")
            if color[v] == WHITE:
                visit(v)
        color[u] = BLACK
        order.append(u)

    for u in list(graph):
        if color[u] == WHITE:
            visit(u)
    return order[::-1]


def is_valid_topo(graph: Dict[Hashable, List[Hashable]], order: List[Hashable]) -> bool:
    pos = {u: i for i, u in enumerate(order)}
    return all(pos[u] < pos[v] for u in graph for v in graph[u] if v in pos)


def test_topo_basic():
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    order = topo_sort_dfs(g)
    assert is_valid_topo(g, order)


def test_topo_linear():
    g = {1: [2], 2: [3], 3: []}
    assert topo_sort_dfs(g) == [1, 2, 3]


def test_topo_cycle():
    g = {"a": ["b"], "b": ["c"], "c": ["a"]}
    try:
        topo_sort_dfs(g)
    except CycleError:
        return
    raise AssertionError("expected CycleError")


def test_topo_disconnected():
    g = {"a": ["b"], "b": [], "c": ["d"], "d": []}
    order = topo_sort_dfs(g)
    assert is_valid_topo(g, order)
    assert sorted(order) == ["a", "b", "c", "d"]


def test_topo_empty():
    assert topo_sort_dfs({}) == []


def main() -> None:
    test_topo_basic()
    test_topo_linear()
    test_topo_cycle()
    test_topo_disconnected()
    test_topo_empty()
    print("graph_07 (topological sort) OK")


if __name__ == "__main__":
    main()
