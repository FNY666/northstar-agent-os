"""graph_36: Transitive closure via Floyd-Warshall reachability. Stdlib only.

GRAPH_36_VERSION = graph-36.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List

GRAPH_36_VERSION = "graph-36.v1"


def transitive_closure(graph: Dict[Hashable, List[Hashable]]) -> Dict[Hashable, List[Hashable]]:
    """Reachability: closure[u] = all nodes reachable from u (excluding u unless cycle)."""
    nodes = list(graph)
    idx = {u: i for i, u in enumerate(nodes)}
    n = len(nodes)
    reach = [[False] * n for _ in range(n)]
    for u in graph:
        for v in graph[u]:
            if v in idx:
                reach[idx[u]][idx[v]] = True
    for k in range(n):
        rk = reach[k]
        for i in range(n):
            if reach[i][k]:
                ri = reach[i]
                for j in range(n):
                    ri[j] = ri[j] or rk[j]
    return {u: [nodes[j] for j in range(n) if reach[idx[u]][j]] for u in nodes}


def test_tc_chain():
    g = {"a": ["b"], "b": ["c"], "c": []}
    tc = transitive_closure(g)
    assert sorted(tc["a"]) == ["b", "c"]
    assert tc["b"] == ["c"] and tc["c"] == []


def test_tc_diamond():
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    tc = transitive_closure(g)
    assert sorted(tc["a"]) == ["b", "c", "d"]


def test_tc_cycle():
    g = {"a": ["b"], "b": ["a"]}
    tc = transitive_closure(g)
    assert sorted(tc["a"]) == ["a", "b"]


def test_tc_disconnected():
    g = {"a": ["b"], "b": [], "c": ["d"], "d": []}
    tc = transitive_closure(g)
    assert "c" not in tc["a"] and tc["c"] == ["d"]


def test_tc_empty():
    assert transitive_closure({}) == {}


def main() -> None:
    test_tc_chain()
    test_tc_diamond()
    test_tc_cycle()
    test_tc_disconnected()
    test_tc_empty()
    print("graph_36 (transitive closure) OK")


if __name__ == "__main__":
    main()
