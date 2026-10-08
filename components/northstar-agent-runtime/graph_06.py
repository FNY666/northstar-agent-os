"""graph_06: A* search with admissible heuristic. Standard library only.

GRAPH_06_VERSION = graph-06.v1
"""
from __future__ import annotations

import heapq
from typing import Callable, Dict, Hashable, List, Optional, Tuple

GRAPH_06_VERSION = "graph-06.v1"


def astar(
    graph: Dict[Hashable, List[Tuple[Hashable, float]]],
    start: Hashable,
    goal: Hashable,
    heuristic: Callable[[Hashable], float],
) -> Optional[List[Hashable]]:
    """A* path from start to goal; heuristic must be admissible. None if unreachable."""
    open_heap: List[Tuple[float, float, Hashable]] = [(heuristic(start), 0.0, start)]
    g_score: Dict[Hashable, float] = {start: 0.0}
    prev: Dict[Hashable, Optional[Hashable]] = {start: None}
    closed = set()
    while open_heap:
        _, g, u = heapq.heappop(open_heap)
        if u in closed:
            continue
        if u == goal:
            path = [u]
            while prev[path[-1]] is not None:
                path.append(prev[path[-1]])  # type: ignore[arg-type]
            return path[::-1]
        closed.add(u)
        for v, w in graph.get(u, []):
            ng = g + w
            if ng < g_score.get(v, float("inf")):
                g_score[v] = ng
                prev[v] = u
                heapq.heappush(open_heap, (ng + heuristic(v), ng, v))
    return None


def manhattan(a: Tuple[int, int], b: Tuple[int, int]) -> float:
    return float(abs(a[0] - b[0]) + abs(a[1] - b[1]))


def grid_graph(rows: int, cols: int, blocked: set) -> Dict[Tuple[int, int], List[Tuple[Tuple[int, int], float]]]:
    g: Dict[Tuple[int, int], List[Tuple[Tuple[int, int], float]]] = {}
    for r in range(rows):
        for c in range(cols):
            if (r, c) in blocked:
                continue
            nbrs = []
            for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                nr, nc = r + dr, c + dc
                if 0 <= nr < rows and 0 <= nc < cols and (nr, nc) not in blocked:
                    nbrs.append(((nr, nc), 1.0))
            g[(r, c)] = nbrs
    return g


def test_astar_grid():
    g = grid_graph(5, 5, {(2, 2)})
    goal = (4, 4)
    path = astar(g, (0, 0), goal, lambda p: manhattan(p, goal))
    assert path is not None
    assert path[0] == (0, 0) and path[-1] == (4, 4)
    assert len(path) - 1 == 8  # optimal length avoids the block


def test_astar_optimal():
    g = {"a": [("b", 1), ("c", 5)], "b": [("c", 1)], "c": []}
    path = astar(g, "a", "c", lambda n: {"a": 2, "b": 1, "c": 0}[n])
    assert path == ["a", "b", "c"]


def test_astar_unreachable():
    g = {"a": [], "b": []}
    assert astar(g, "a", "b", lambda n: 0) is None


def test_astar_start_is_goal():
    g = {"a": [("b", 1)], "b": []}
    assert astar(g, "a", "a", lambda n: 0) == ["a"]


def main() -> None:
    test_astar_grid()
    test_astar_optimal()
    test_astar_unreachable()
    test_astar_start_is_goal()
    print("graph_06 (A*) OK")


if __name__ == "__main__":
    main()
