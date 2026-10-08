"""Kosaraju's strongly connected components algorithm.

Two passes: (1) DFS on the graph recording finish order; (2) DFS on the
transpose (reversed) graph in reverse finish order, each tree found being
one strongly connected component.

Time complexity: O(V + E). Space: O(V + E).
"""

from typing import Dict, List

ALGO_27_VERSION = "algo-27.v1"

_STDLIB_USED = {"typing", "ast", "pathlib"}


def kosaraju_scc(graph: Dict) -> List[List]:
    """Return the strongly connected components of ``graph``."""
    nodes = list(graph)
    for nbrs in graph.values():
        for nb in nbrs:
            if nb not in graph and nb not in nodes:
                nodes.append(nb)

    rev: Dict = {n: [] for n in nodes}
    for u, nbrs in graph.items():
        for v in nbrs:
            rev[v].append(u)

    visited = set()
    finish: List = []

    def dfs1(v):
        visited.add(v)
        for w in graph.get(v, []):
            if w not in visited:
                dfs1(w)
        finish.append(v)

    for v in nodes:
        if v not in visited:
            dfs1(v)

    seen = set()
    result: List[List] = []

    def dfs2(v, comp):
        seen.add(v)
        comp.append(v)
        for w in rev[v]:
            if w not in seen:
                dfs2(w, comp)

    for v in reversed(finish):
        if v not in seen:
            comp: List = []
            dfs2(v, comp)
            result.append(comp)
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
    assert _norm(kosaraju_scc(g)) == {
        frozenset({"A", "B", "C"}), frozenset({"D"}), frozenset({"E"})
    }, kosaraju_scc(g)
    assert kosaraju_scc({}) == []
    assert kosaraju_scc({"X": ["X"]}) == [["X"]]
    assert _norm(kosaraju_scc({"A": [], "B": []})) == {frozenset({"A"}), frozenset({"B"})}
    assert _norm(kosaraju_scc({"A": ["B"], "B": ["A"], "C": ["D"], "D": []})) == {
        frozenset({"A", "B"}), frozenset({"C"}), frozenset({"D"})
    }
    assert stdlib_only() is True
    print("algo_27 OK")


if __name__ == "__main__":
    main()
