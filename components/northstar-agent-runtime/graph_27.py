"""graph_27: Biconnected components (edge-based) via DFS stack. Stdlib only.

GRAPH_27_VERSION = graph-27.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Tuple

GRAPH_27_VERSION = "graph-27.v1"

Edge = Tuple[Hashable, Hashable]


def biconnected_components(graph: Dict[Hashable, List[Hashable]]) -> List[List[Edge]]:
    """Edge-biconnected components; each is a list of edges."""
    disc: Dict[Hashable, int] = {}
    low: Dict[Hashable, int] = {}
    stack: List[Edge] = []
    comps: List[List[Edge]] = []
    timer = [0]

    def dfs(u: Hashable, parent: Hashable | None) -> None:
        disc[u] = low[u] = timer[0]
        timer[0] += 1
        for v in graph.get(u, []):
            e = (u, v)
            if v == parent:
                continue
            if v not in disc:
                stack.append(e)
                dfs(v, u)
                low[u] = min(low[u], low[v])
                if low[v] >= disc[u]:
                    comp = []
                    while True:
                        comp.append(stack.pop())
                        if comp[-1] == e or comp[-1] == (v, u):
                            break
                    comps.append(comp)
            elif disc[v] < disc[u]:
                stack.append(e)
                low[u] = min(low[u], disc[v])

    for u in graph:
        if u not in disc:
            dfs(u, None)
            if stack:
                comps.append(list(stack))
                stack.clear()
    return comps


def _norm(edges: List[Edge]) -> List[Tuple[str, str]]:
    return sorted((repr(a), repr(b)) for a, b in edges)


def test_bcc_triangle_plus_bridge():
    g = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b", "d"], "d": ["c"]}
    comps = biconnected_components(g)
    assert len(comps) == 2
    sizes = sorted(len(c) for c in comps)
    assert sizes == [1, 3]  # bridge + triangle


def test_bcc_single_cycle():
    g = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c", "a"]}
    comps = biconnected_components(g)
    assert len(comps) == 1 and len(comps[0]) == 4


def test_bcc_path():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    comps = biconnected_components(g)
    assert len(comps) == 2 and all(len(c) == 1 for c in comps)


def test_bcc_covers_all_edges():
    g = {"a": ["b", "c", "d"], "b": ["a", "c"], "c": ["a", "b"],
         "d": ["a", "e"], "e": ["d"]}
    comps = biconnected_components(g)
    total = sum(len(c) for c in comps)
    expected = sum(len(nbrs) for nbrs in g.values()) // 2
    assert total == expected


def test_bcc_single_node():
    assert biconnected_components({"a": []}) == []


def main() -> None:
    test_bcc_triangle_plus_bridge()
    test_bcc_single_cycle()
    test_bcc_path()
    test_bcc_covers_all_edges()
    test_bcc_single_node()
    print("graph_27 (biconnected components) OK")


if __name__ == "__main__":
    main()
