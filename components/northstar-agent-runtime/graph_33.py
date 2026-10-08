"""graph_33: Directed cycle detection (3-color DFS). Standard library only.

GRAPH_33_VERSION = graph-33.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Optional

GRAPH_33_VERSION = "graph-33.v1"


def find_directed_cycle(graph: Dict[Hashable, List[Hashable]]) -> Optional[List[Hashable]]:
    """Returns one directed cycle as a node list, or None if acyclic."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color: Dict[Hashable, int] = {u: WHITE for u in graph}
    stack: List[Hashable] = []
    result: List[Optional[List[Hashable]]] = [None]

    def visit(u: Hashable) -> bool:
        color[u] = GRAY
        stack.append(u)
        for v in graph.get(u, []):
            if v not in color:
                color[v] = WHITE
            if color[v] == GRAY:
                result[0] = stack[stack.index(v):] + [v]
                return True
            if color[v] == WHITE and visit(v):
                return True
        stack.pop()
        color[u] = BLACK
        return False

    for u in list(graph):
        if color[u] == WHITE and visit(u):
            break
    return result[0]


def has_directed_cycle(graph: Dict[Hashable, List[Hashable]]) -> bool:
    return find_directed_cycle(graph) is not None


def _is_cycle(graph: Dict[Hashable, List[Hashable]], cyc: List[Hashable]) -> bool:
    return all(cyc[i + 1] in graph.get(cyc[i], []) for i in range(len(cyc) - 1))


def test_directed_cycle_found():
    g = {"a": ["b"], "b": ["c"], "c": ["a", "d"], "d": []}
    cyc = find_directed_cycle(g)
    assert cyc is not None and _is_cycle(g, cyc)


def test_directed_cycle_self_loop():
    g = {"a": ["a"]}
    assert find_directed_cycle(g) == ["a", "a"]


def test_directed_cycle_absent():
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    assert has_directed_cycle(g) is False
    assert find_directed_cycle(g) is None


def test_directed_cycle_two_node():
    g = {"a": ["b"], "b": ["a"]}
    cyc = find_directed_cycle(g)
    assert cyc is not None and set(cyc) == {"a", "b"}


def test_directed_cycle_empty():
    assert has_directed_cycle({}) is False


def main() -> None:
    test_directed_cycle_found()
    test_directed_cycle_self_loop()
    test_directed_cycle_absent()
    test_directed_cycle_two_node()
    test_directed_cycle_empty()
    print("graph_33 (directed cycle) OK")


if __name__ == "__main__":
    main()
