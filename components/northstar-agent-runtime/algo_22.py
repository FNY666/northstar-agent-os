"""Kruskal's minimum spanning tree algorithm.

Sorts edges by weight and greedily adds the cheapest edge that connects
two different components, tracked with a union-find (disjoint set) structure
using path compression and union by rank.

Time complexity: O(E log E) for the sort; union-find ops are near O(1)
(inverse Ackermann). Space: O(V).
"""

from typing import Dict, List, Tuple

ALGO_22_VERSION = "algo-22.v1"

_STDLIB_USED = {"typing", "ast", "pathlib"}


def kruskal(nodes: List, edges: List[Tuple]) -> Tuple[List[Tuple], float]:
    """Return (mst_edges, total_weight) for an undirected weighted graph.

    ``edges`` is a list of (u, v, w). Nodes named in edges but missing from
    ``nodes`` are added automatically. For a disconnected graph this returns
    a minimum spanning forest (no error).
    """
    parent: Dict = {}
    rank: Dict = {}

    def make(x):
        if x not in parent:
            parent[x] = x
            rank[x] = 0

    for n in nodes:
        make(n)
    for u, v, _w in edges:
        make(u)
        make(v)

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path compression (halving)
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra == rb:
            return False
        if rank[ra] < rank[rb]:
            ra, rb = rb, ra
        parent[rb] = ra
        if rank[ra] == rank[rb]:
            rank[ra] += 1
        return True

    mst = []
    total = 0
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        if union(u, v):
            mst.append((u, v, w))
            total += w
    return mst, total


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


def main() -> None:
    edges = [(0, 1, 10), (0, 2, 6), (0, 3, 5), (1, 3, 15), (2, 3, 4)]
    mst, total = kruskal([0, 1, 2, 3], edges)
    assert total == 19, total
    assert mst == [(2, 3, 4), (0, 3, 5), (0, 1, 10)], mst
    mst2, total2 = kruskal([], [])
    assert mst2 == [] and total2 == 0
    mst3, total3 = kruskal(["A"], [])
    assert mst3 == [] and total3 == 0
    mst4, total4 = kruskal([1, 2, 3, 4], [(1, 2, 1), (3, 4, 2)])
    assert total4 == 3 and len(mst4) == 2  # disconnected -> forest
    assert stdlib_only() is True
    print("algo_22 OK")


if __name__ == "__main__":
    main()
