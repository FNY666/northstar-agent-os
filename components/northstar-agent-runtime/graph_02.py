"""graph_02: Depth-first search (DFS), iterative and recursive. Standard library only.

GRAPH_02_VERSION = graph-02.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Optional, Set

GRAPH_02_VERSION = "graph-02.v1"


def dfs_order(graph: Dict[Hashable, List[Hashable]], start: Hashable) -> List[Hashable]:
    """Iterative DFS preorder."""
    seen: Set[Hashable] = set()
    order: List[Hashable] = []
    stack = [start]
    while stack:
        u = stack.pop()
        if u in seen:
            continue
        seen.add(u)
        order.append(u)
        for v in reversed(graph.get(u, [])):
            if v not in seen:
                stack.append(v)
    return order


def dfs_recursive(graph: Dict[Hashable, List[Hashable]], start: Hashable) -> List[Hashable]:
    """Recursive DFS preorder."""
    seen: Set[Hashable] = set()
    order: List[Hashable] = []

    def visit(u: Hashable) -> None:
        seen.add(u)
        order.append(u)
        for v in graph.get(u, []):
            if v not in seen:
                visit(v)

    visit(start)
    return order


def dfs_path(
    graph: Dict[Hashable, List[Hashable]], start: Hashable, goal: Hashable
) -> Optional[List[Hashable]]:
    """Any path from start to goal via DFS, or None."""
    seen: Set[Hashable] = set()
    path: List[Hashable] = []

    def visit(u: Hashable) -> bool:
        seen.add(u)
        path.append(u)
        if u == goal:
            return True
        for v in graph.get(u, []):
            if v not in seen and visit(v):
                return True
        path.pop()
        return False

    return path if visit(start) else None


def test_dfs_order_visits_all():
    g = {"a": ["b", "c"], "b": ["d"], "c": [], "d": []}
    assert sorted(dfs_order(g, "a")) == ["a", "b", "c", "d"]
    assert dfs_order(g, "a")[0] == "a"


def test_dfs_recursive_matches_iterative():
    g = {0: [1, 2], 1: [3], 2: [3], 3: []}
    assert sorted(dfs_recursive(g, 0)) == sorted(dfs_order(g, 0)) == [0, 1, 2, 3]


def test_dfs_path_found():
    g = {"a": ["b"], "b": ["c"], "c": []}
    assert dfs_path(g, "a", "c") == ["a", "b", "c"]


def test_dfs_path_missing():
    g = {"a": ["b"], "b": [], "c": []}
    assert dfs_path(g, "a", "c") is None


def test_dfs_handles_cycle():
    g = {"a": ["b"], "b": ["c"], "c": ["a"]}
    assert sorted(dfs_order(g, "a")) == ["a", "b", "c"]


def main() -> None:
    test_dfs_order_visits_all()
    test_dfs_recursive_matches_iterative()
    test_dfs_path_found()
    test_dfs_path_missing()
    test_dfs_handles_cycle()
    print("graph_02 (DFS) OK")


if __name__ == "__main__":
    main()
