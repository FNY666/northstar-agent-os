"""graph_48: All simple paths between two nodes (bounded DFS). Stdlib only.

GRAPH_48_VERSION = graph-48.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Optional

GRAPH_48_VERSION = "graph-48.v1"


def all_simple_paths(
    graph: Dict[Hashable, List[Hashable]],
    start: Hashable,
    goal: Hashable,
    max_paths: int = 10000,
    max_depth: Optional[int] = None,
) -> List[List[Hashable]]:
    """Enumerate simple paths up to max_paths / max_depth caps."""
    paths: List[List[Hashable]] = []
    stack: List[Hashable] = [start]
    seen = {start}

    def dfs() -> None:
        if len(paths) >= max_paths:
            return
        u = stack[-1]
        if u == goal:
            paths.append(list(stack))
            return
        if max_depth is not None and len(stack) > max_depth:
            return
        for v in graph.get(u, []):
            if v not in seen:
                seen.add(v)
                stack.append(v)
                dfs()
                stack.pop()
                seen.discard(v)

    dfs()
    return paths


def test_all_paths_diamond():
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    paths = all_simple_paths(g, "a", "d")
    assert sorted(paths) == [["a", "b", "d"], ["a", "c", "d"]]


def test_all_paths_none():
    g = {"a": ["b"], "b": [], "c": []}
    assert all_simple_paths(g, "a", "c") == []


def test_all_paths_start_is_goal():
    g = {"a": ["b"], "b": []}
    assert all_simple_paths(g, "a", "a") == [["a"]]


def test_all_paths_cap():
    # complete-ish digraph: cap kicks in
    nodes = list(range(6))
    g = {u: [v for v in nodes if v != u] for u in nodes}
    paths = all_simple_paths(g, 0, 5, max_paths=50)
    assert len(paths) == 50


def test_all_paths_depth_cap():
    g = {"a": ["b"], "b": ["c"], "c": ["d"], "d": []}
    assert all_simple_paths(g, "a", "d", max_depth=2) == []


def main() -> None:
    test_all_paths_diamond()
    test_all_paths_none()
    test_all_paths_start_is_goal()
    test_all_paths_cap()
    test_all_paths_depth_cap()
    print("graph_48 (all simple paths) OK")


if __name__ == "__main__":
    main()
