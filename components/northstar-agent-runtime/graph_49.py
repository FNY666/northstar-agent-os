"""graph_49: Widest path (maximum capacity path). Standard library only.

GRAPH_49_VERSION = graph-49.v1
"""
from __future__ import annotations

import heapq
from typing import Dict, Hashable, List, Optional, Tuple

GRAPH_49_VERSION = "graph-49.v1"


def widest_path(
    graph: Dict[Hashable, List[Tuple[Hashable, float]]], start: Hashable, goal: Hashable
) -> Tuple[float, Optional[List[Hashable]]]:
    """Maximize the bottleneck edge along the path. Returns (width, path)."""
    width: Dict[Hashable, float] = {start: float("inf")}
    prev: Dict[Hashable, Optional[Hashable]] = {start: None}
    pq: List[Tuple[float, Hashable]] = [(-float("inf"), start)]
    done = set()
    while pq:
        negw, u = heapq.heappop(pq)
        w = -negw
        if u in done:
            continue
        done.add(u)
        if u == goal:
            break
        for v, c in graph.get(u, []):
            nw = min(w, c)
            if nw > width.get(v, 0.0):
                width[v] = nw
                prev[v] = u
                heapq.heappush(pq, (-nw, v))
    if goal not in width:
        return 0.0, None
    path = [goal]
    while prev[path[-1]] is not None:
        path.append(prev[path[-1]])  # type: ignore[arg-type]
    return width[goal], path[::-1]


def test_widest_basic():
    g = {"s": [("a", 5), ("b", 3)], "a": [("t", 4)], "b": [("t", 10)], "t": []}
    w, p = widest_path(g, "s", "t")
    assert w == 4.0 and p == ["s", "a", "t"]


def test_widest_prefers_fat_pipe():
    g = {"s": [("a", 100), ("b", 2)], "a": [("t", 100)], "b": [("t", 2)], "t": []}
    w, p = widest_path(g, "s", "t")
    assert w == 100.0 and p == ["s", "a", "t"]


def test_widest_unreachable():
    g = {"s": [("a", 5)], "a": [], "t": []}
    w, p = widest_path(g, "s", "t")
    assert w == 0.0 and p is None


def test_widest_single_edge():
    w, p = widest_path({"s": [("t", 7)]}, "s", "t")
    assert w == 7.0 and p == ["s", "t"]


def test_widest_bottleneck_middle():
    g = {"s": [("a", 9)], "a": [("b", 1)], "b": [("t", 9)], "t": []}
    w, _ = widest_path(g, "s", "t")
    assert w == 1.0


def main() -> None:
    test_widest_basic()
    test_widest_prefers_fat_pipe()
    test_widest_unreachable()
    test_widest_single_edge()
    test_widest_bottleneck_middle()
    print("graph_49 (widest path) OK")


if __name__ == "__main__":
    main()
