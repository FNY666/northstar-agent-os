"""graph_08: Kahn's algorithm for topological sorting. Standard library only.

GRAPH_08_VERSION = graph-08.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List

GRAPH_08_VERSION = "graph-08.v1"


class CycleError(ValueError):
    """Raised when the graph is not a DAG."""


def kahn_topo_sort(graph: Dict[Hashable, List[Hashable]]) -> List[Hashable]:
    """Kahn's BFS topological sort; raises CycleError on cycles."""
    indeg: Dict[Hashable, int] = {u: 0 for u in graph}
    for u in graph:
        for v in graph[u]:
            indeg[v] = indeg.get(v, 0) + 1
    q: deque = deque([u for u, d in indeg.items() if d == 0])
    order: List[Hashable] = []
    while q:
        u = q.popleft()
        order.append(u)
        for v in graph.get(u, []):
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    if len(order) != len(indeg):
        raise CycleError("graph has a cycle")
    return order


def course_schedule_possible(num: int, prereqs: List[tuple]) -> bool:
    """Classic application: can all courses be finished?"""
    graph = {i: [] for i in range(num)}
    for course, pre in prereqs:
        graph[pre].append(course)
    try:
        kahn_topo_sort(graph)
        return True
    except CycleError:
        return False


def test_kahn_basic():
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    order = kahn_topo_sort(g)
    pos = {u: i for i, u in enumerate(order)}
    assert all(pos[u] < pos[v] for u in g for v in g[u])


def test_kahn_cycle():
    g = {"a": ["b"], "b": ["a"]}
    try:
        kahn_topo_sort(g)
    except CycleError:
        return
    raise AssertionError("expected CycleError")


def test_kahn_course_possible():
    assert course_schedule_possible(2, [(1, 0)]) is True


def test_kahn_course_impossible():
    assert course_schedule_possible(2, [(1, 0), (0, 1)]) is False


def test_kahn_single():
    assert kahn_topo_sort({"a": []}) == ["a"]


def main() -> None:
    test_kahn_basic()
    test_kahn_cycle()
    test_kahn_course_possible()
    test_kahn_course_impossible()
    test_kahn_single()
    print("graph_08 (Kahn's) OK")


if __name__ == "__main__":
    main()
