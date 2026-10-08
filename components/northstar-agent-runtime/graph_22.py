"""graph_22: Eulerian trail/circuit existence checks. Standard library only.

GRAPH_22_VERSION = graph-22.v1
"""
from __future__ import annotations

from collections import Counter, deque
from typing import Dict, Hashable, List

GRAPH_22_VERSION = "graph-22.v1"


def _degrees(graph: Dict[Hashable, List[Hashable]]) -> Counter:
    deg: Counter = Counter()
    for u, nbrs in graph.items():
        deg[u] += len(nbrs)
    return deg


def _connected_nonzero(graph: Dict[Hashable, List[Hashable]]) -> bool:
    deg = _degrees(graph)
    start = next((u for u, d in deg.items() if d > 0), None)
    if start is None:
        return True
    seen = {start}
    q: deque = deque([start])
    while q:
        u = q.popleft()
        for v in graph.get(u, []):
            if v not in seen:
                seen.add(v)
                q.append(v)
    return all(d == 0 or u in seen for u, d in deg.items())


def has_eulerian_circuit(graph: Dict[Hashable, List[Hashable]]) -> bool:
    """Undirected: all even degrees + connected (ignoring isolated)."""
    if not _connected_nonzero(graph):
        return False
    return all(d % 2 == 0 for d in _degrees(graph).values())


def has_eulerian_trail(graph: Dict[Hashable, List[Hashable]]) -> bool:
    """Undirected: 0 or 2 odd degrees + connected."""
    if not _connected_nonzero(graph):
        return False
    odd = sum(d % 2 for d in _degrees(graph).values())
    return odd in (0, 2)


def test_eulerian_circuit_square():
    g = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c", "a"]}
    assert has_eulerian_circuit(g) is True
    assert has_eulerian_trail(g) is True


def test_eulerian_trail_path():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    assert has_eulerian_circuit(g) is False
    assert has_eulerian_trail(g) is True


def test_eulerian_star_no_trail():
    g = {"c": ["a", "b", "d", "e"], "a": ["c"], "b": ["c"], "d": ["c"], "e": ["c"]}
    assert has_eulerian_trail(g) is False
    assert has_eulerian_circuit(g) is False


def test_eulerian_empty():
    assert has_eulerian_circuit({}) is True
    assert has_eulerian_trail({}) is True


def test_eulerian_disconnected():
    g = {"a": ["b"], "b": ["a"], "c": ["d"], "d": ["c"]}
    assert has_eulerian_circuit(g) is False


def main() -> None:
    test_eulerian_circuit_square()
    test_eulerian_trail_path()
    test_eulerian_star_no_trail()
    test_eulerian_empty()
    test_eulerian_disconnected()
    print("graph_22 (Eulerian check) OK")


if __name__ == "__main__":
    main()
