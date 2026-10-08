"""graph_24: Fleury's algorithm for Eulerian trails. Standard library only.

GRAPH_24_VERSION = graph-24.v1
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, Hashable, List, Optional

GRAPH_24_VERSION = "graph-24.v1"


def _is_bridge(adj: Dict[Hashable, List[Hashable]], u: Hashable, v: Hashable) -> bool:
    """True if edge u-v is a bridge in the current multigraph."""
    if len(adj.get(u, [])) == 1:
        return True  # only edge: must take it
    # count reachable from u without using edge u-v
    seen = {u}
    stack = [u]
    while stack:
        x = stack.pop()
        for y in adj.get(x, []):
            if (x == u and y == v) or (x == v and y == u):
                continue
            if y not in seen:
                seen.add(y)
                stack.append(y)
    return v not in seen


def fleury(graph: Dict[Hashable, List[Hashable]]) -> Optional[List[Hashable]]:
    """Fleury's Eulerian trail; avoids bridges unless forced. None if none exists."""
    adj: Dict[Hashable, List[Hashable]] = {u: list(nbrs) for u, nbrs in graph.items()}
    deg = Counter()
    for u, nbrs in adj.items():
        deg[u] += len(nbrs)
    odd = [u for u, d in deg.items() if d % 2 == 1]
    if len(odd) not in (0, 2):
        return None
    start = odd[0] if odd else next((u for u, d in deg.items() if d > 0), None)
    if start is None:
        return []
    trail = [start]
    u = start
    while adj.get(u):
        # prefer non-bridge edges
        nxt = None
        for v in adj[u]:
            if not _is_bridge(adj, u, v):
                nxt = v
                break
        if nxt is None:
            nxt = adj[u][0]
        adj[u].remove(nxt)
        adj[nxt].remove(u)
        trail.append(nxt)
        u = nxt
    if any(adj[x] for x in adj):
        return None
    return trail


def _valid(graph: Dict[Hashable, List[Hashable]], trail: List[Hashable]) -> bool:
    rem = Counter()
    for u, nbrs in graph.items():
        for v in nbrs:
            rem[(u, v)] += 1
    for a, b in zip(trail, trail[1:]):
        if rem[(a, b)]:
            rem[(a, b)] -= 1
        elif rem[(b, a)]:
            rem[(b, a)] -= 1
        else:
            return False
    return all(c == 0 for c in rem.values())


def test_fleury_square():
    g = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c", "a"]}
    t = fleury(g)
    assert t is not None and len(t) == 5 and _valid(g, t)


def test_fleury_trail():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    t = fleury(g)
    assert t is not None and _valid(g, t) and {t[0], t[-1]} == {"a", "c"}


def test_fleury_none():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    assert fleury(g) is None


def test_fleury_dumbbell():
    # two triangles joined by a bridge: must cross bridge exactly once
    g = {"a": ["b", "c", "d"], "b": ["a", "c"], "c": ["a", "b"],
         "d": ["a", "e", "f"], "e": ["d", "f"], "f": ["d", "e"]}
    t = fleury(g)
    assert t is not None and _valid(g, t)


def test_fleury_agrees_with_hierholzer():
    import sys
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    import graph_23

    g = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c", "a"]}
    assert (fleury(g) is not None) == (graph_23.hierholzer(g) is not None)


def main() -> None:
    test_fleury_square()
    test_fleury_trail()
    test_fleury_none()
    test_fleury_dumbbell()
    test_fleury_agrees_with_hierholzer()
    print("graph_24 (Fleury) OK")


if __name__ == "__main__":
    main()
