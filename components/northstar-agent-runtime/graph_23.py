"""graph_23: Hierholzer's algorithm for Eulerian circuits/trails. Stdlib only.

GRAPH_23_VERSION = graph-23.v1
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, Hashable, List, Optional

GRAPH_23_VERSION = "graph-23.v1"


def hierholzer(graph: Dict[Hashable, List[Hashable]]) -> Optional[List[Hashable]]:
    """Eulerian circuit/trail via Hierholzer. None if none exists.

    Multigraph-safe: consumes edge copies.
    """
    # copy adjacency as mutable lists
    adj: Dict[Hashable, List[Hashable]] = {u: list(nbrs) for u, nbrs in graph.items()}
    deg = Counter()
    for u, nbrs in adj.items():
        deg[u] += len(nbrs)
        for v in nbrs:
            deg[v] += 0  # ensure presence
    odd = [u for u, d in deg.items() if d % 2 == 1]
    if len(odd) not in (0, 2):
        return None
    start = odd[0] if odd else next((u for u, d in deg.items() if d > 0), None)
    if start is None:
        return []
    # remove one undirected edge copy u-v
    def remove_edge(u: Hashable, v: Hashable) -> None:
        adj[u].remove(v)
        adj[v].remove(u)

    stack = [start]
    circuit: List[Hashable] = []
    while stack:
        u = stack[-1]
        if adj.get(u):
            v = adj[u][0]
            remove_edge(u, v)
            stack.append(v)
        else:
            circuit.append(stack.pop())
    circuit.reverse()
    # verify all edges consumed
    if any(adj[u] for u in adj):
        return None
    return circuit


def _is_valid_trail(graph: Dict[Hashable, List[Hashable]], trail: List[Hashable]) -> bool:
    if not trail:
        return True
    remaining = Counter()
    for u, nbrs in graph.items():
        for v in nbrs:
            remaining[(u, v)] += 1
    for a, b in zip(trail, trail[1:]):
        if remaining[(a, b)] > 0:
            remaining[(a, b)] -= 1
        elif remaining[(b, a)] > 0:
            remaining[(b, a)] -= 1
        else:
            return False
    return all(c == 0 for c in remaining.values())


def test_hierholzer_square():
    g = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c", "a"]}
    t = hierholzer(g)
    assert t is not None and t[0] == t[-1] and len(t) == 5
    assert _is_valid_trail(g, t)


def test_hierholzer_trail():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    t = hierholzer(g)
    assert t is not None and {t[0], t[-1]} == {"a", "c"}
    assert _is_valid_trail(g, t)


def test_hierholzer_none():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    assert hierholzer(g) is None


def test_hierholzer_konigsberg():
    # classic: no Eulerian trail
    g = {"a": ["b", "b", "c"], "b": ["a", "a", "c", "d", "d"],
         "c": ["a", "b", "d"], "d": ["b", "b", "c"]}
    assert hierholzer(g) is None


def test_hierholzer_multigraph():
    g = {"a": ["b", "b"], "b": ["a", "a"]}
    t = hierholzer(g)
    assert t is not None and len(t) == 3 and _is_valid_trail(g, t)


def main() -> None:
    test_hierholzer_square()
    test_hierholzer_trail()
    test_hierholzer_none()
    test_hierholzer_konigsberg()
    test_hierholzer_multigraph()
    print("graph_23 (Hierholzer) OK")


if __name__ == "__main__":
    main()
