"""Prim's minimum spanning tree algorithm (lazy heap version).

Grows the tree from ``start`` by always extracting the cheapest edge that
reaches a node outside the tree, using a heapq priority queue.

Time complexity: O(E log V). Space: O(V + E).
For a disconnected graph this returns the MST of ``start``'s component.
"""

import heapq
from typing import Dict, List, Tuple

ALGO_23_VERSION = "algo-23.v1"

_STDLIB_USED = {"typing", "heapq", "ast", "pathlib"}


def prim(graph: Dict, start) -> Tuple[List[Tuple], float]:
    """Return (mst_edges, total_weight) growing from ``start``.

    ``graph`` is dict node -> dict neighbor -> weight (undirected: both
    directions present). Each mst edge is (u, v, w) with u already in the
    tree when the edge was picked.
    """
    visited = {start}
    heap = [(w, start, nb) for nb, w in graph.get(start, {}).items()]
    heapq.heapify(heap)
    mst: List[Tuple] = []
    total = 0
    while heap:
        w, u, v = heapq.heappop(heap)
        if v in visited:
            continue
        visited.add(v)
        mst.append((u, v, w))
        total += w
        for nb, w2 in graph.get(v, {}).items():
            if nb not in visited:
                heapq.heappush(heap, (w2, v, nb))
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


def _norm(edges):
    return {(frozenset((u, v)), w) for u, v, w in edges}


def main() -> None:
    g = {
        0: {1: 10, 2: 6, 3: 5},
        1: {0: 10, 3: 15},
        2: {0: 6, 3: 4},
        3: {0: 5, 1: 15, 2: 4},
    }
    mst, total = prim(g, 0)
    assert total == 19, total
    assert _norm(mst) == {
        (frozenset((0, 3)), 5),
        (frozenset((2, 3)), 4),
        (frozenset((0, 1)), 10),
    }, mst
    mst2, total2 = prim({"A": {}}, "A")
    assert mst2 == [] and total2 == 0
    mst3, total3 = prim({0: {1: 7}, 1: {0: 7}, 9: {}}, 0)
    assert total3 == 7 and len(mst3) == 1  # disconnected component ignored
    mst4, total4 = prim({0: {1: 3, 2: 1}, 1: {0: 3}, 2: {0: 1}}, 0)
    assert total4 == 4, total4
    assert stdlib_only() is True
    print("algo_23 OK")


if __name__ == "__main__":
    main()
