"""graph_09: Tarjan's strongly connected components. Standard library only.

GRAPH_09_VERSION = graph-09.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Set

GRAPH_09_VERSION = "graph-09.v1"


def tarjan_scc(graph: Dict[Hashable, List[Hashable]]) -> List[List[Hashable]]:
    """Tarjan's SCC; returns list of components (each a list of nodes)."""
    index_of: Dict[Hashable, int] = {}
    low: Dict[Hashable, int] = {}
    on_stack: Set[Hashable] = set()
    stack: List[Hashable] = []
    result: List[List[Hashable]] = []
    counter = [0]

    def strongconnect(v: Hashable) -> None:
        index_of[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in graph.get(v, []):
            if w not in index_of:
                strongconnect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index_of[w])
        if low[v] == index_of[v]:
            comp = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            result.append(comp)

    for v in graph:
        if v not in index_of:
            strongconnect(v)
    # include nodes only referenced as neighbors
    return result


def condensation_dag_size(graph: Dict[Hashable, List[Hashable]]) -> int:
    """Number of SCCs."""
    return len(tarjan_scc(graph))


def test_tarjan_two_components():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["d"], "d": ["c"], "e": []}
    comps = [sorted(c) for c in tarjan_scc(g)]
    assert sorted(map(tuple, comps)) == [("a", "b"), ("c", "d"), ("e",)]


def test_tarjan_single_cycle():
    g = {"a": ["b"], "b": ["c"], "c": ["a"]}
    comps = tarjan_scc(g)
    assert len(comps) == 1 and sorted(comps[0]) == ["a", "b", "c"]


def test_tarjan_dag():
    g = {"a": ["b"], "b": ["c"], "c": []}
    assert condensation_dag_size(g) == 3


def test_tarjan_self_loop():
    g = {"a": ["a"], "b": []}
    comps = [sorted(c) for c in tarjan_scc(g)]
    assert ["a"] in comps and ["b"] in comps


def test_tarjan_empty():
    assert tarjan_scc({}) == []


def main() -> None:
    test_tarjan_two_components()
    test_tarjan_single_cycle()
    test_tarjan_dag()
    test_tarjan_self_loop()
    test_tarjan_empty()
    print("graph_09 (Tarjan SCC) OK")


if __name__ == "__main__":
    main()
