"""graph_45: Hamiltonian path via backtracking (exact, small graphs). Stdlib only.

GRAPH_45_VERSION = graph-45.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Optional, Set

GRAPH_45_VERSION = "graph-45.v1"


def hamiltonian_path(
    graph: Dict[Hashable, List[Hashable]], start: Optional[Hashable] = None
) -> Optional[List[Hashable]]:
    """Hamiltonian path visiting every vertex once. None if none exists.

    Exact backtracking; exponential worst case -- for small graphs only.
    """
    nodes = list(graph)
    n = len(nodes)
    if n == 0:
        return []
    starts = [start] if start is not None else nodes
    for s in starts:
        path = [s]
        seen = {s}

        def backtrack() -> Optional[List[Hashable]]:
            if len(path) == n:
                return list(path)
            u = path[-1]
            for v in graph.get(u, []):
                if v not in seen:
                    seen.add(v)
                    path.append(v)
                    r = backtrack()
                    if r is not None:
                        return r
                    path.pop()
                    seen.discard(v)
            return None

        r = backtrack()
        if r is not None:
            return r
    return None


def _valid(graph: Dict[Hashable, List[Hashable]], path: List[Hashable]) -> bool:
    return (
        sorted(path) == sorted(graph)
        and len(set(path)) == len(path)
        and all(path[i + 1] in graph.get(path[i], []) for i in range(len(path) - 1))
    )


def test_hamiltonian_path_graph():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c"]}
    p = hamiltonian_path(g)
    assert p is not None and _valid(g, p)


def test_hamiltonian_cycle_graph():
    g = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c", "a"]}
    p = hamiltonian_path(g)
    assert p is not None and _valid(g, p)


def test_hamiltonian_star_none():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    assert hamiltonian_path(g) is None


def test_hamiltonian_fixed_start():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    p = hamiltonian_path(g, start="a")
    assert p == ["a", "b", "c"]
    assert hamiltonian_path(g, start="b") is None


def test_hamiltonian_single():
    assert hamiltonian_path({"a": []}) == ["a"]


def main() -> None:
    test_hamiltonian_path_graph()
    test_hamiltonian_cycle_graph()
    test_hamiltonian_star_none()
    test_hamiltonian_fixed_start()
    test_hamiltonian_single()
    print("graph_45 (Hamiltonian path) OK")


if __name__ == "__main__":
    main()
