"""Tarjan's strongly connected components algorithm.

Single depth-first search that assigns each node an index and a low-link
value; nodes are pushed on a stack, and a root of an SCC (low == index)
pops its whole component.

Time complexity: O(V + E). Space: O(V).
"""

from typing import Dict, List

ALGO_26_VERSION = "algo-26.v1"

_STDLIB_USED = {"typing", "ast", "pathlib"}


def tarjan_scc(graph: Dict) -> List[List]:
    """Return the strongly connected components of ``graph`` (recursive)."""
    nodes = list(graph)
    for nbrs in graph.values():
        for nb in nbrs:
            if nb not in graph and nb not in nodes:
                nodes.append(nb)

    index: Dict = {}
    low: Dict = {}
    on_stack = set()
    stack: List = []
    result: List[List] = []
    counter = [0]

    def strongconnect(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in graph.get(v, []):
            if w not in index:
                strongconnect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            result.append(comp)

    for v in nodes:
        if v not in index:
            strongconnect(v)
    return result


def stdlib_only() -> bool:
    """Assert every imported top-level module is one actually used from the stdlib."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= _STDLIB_USED, f"non-stdlib/unused import: {imported - _STDLIB_USED}"
    return True


def _norm(sccs):
    return {frozenset(c) for c in sccs}


def main() -> None:
    g = {"A": ["B"], "B": ["C"], "C": ["A", "D"], "D": ["E"], "E": []}
    assert _norm(tarjan_scc(g)) == {
        frozenset({"A", "B", "C"}), frozenset({"D"}), frozenset({"E"})
    }, tarjan_scc(g)
    assert tarjan_scc({}) == []
    assert tarjan_scc({"X": ["X"]}) == [["X"]]
    assert _norm(tarjan_scc({"A": [], "B": []})) == {frozenset({"A"}), frozenset({"B"})}
    assert _norm(tarjan_scc({"A": ["B"], "B": ["A"], "C": ["D"], "D": []})) == {
        frozenset({"A", "B"}), frozenset({"C"}), frozenset({"D"})
    }
    assert stdlib_only() is True
    print("algo_26 OK")


if __name__ == "__main__":
    main()
