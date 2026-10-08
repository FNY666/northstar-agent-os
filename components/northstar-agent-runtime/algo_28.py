"""Bipartite check via two-coloring (BFS).

Assigns each node one of two colors; a graph is bipartite iff no edge
connects two nodes of the same color. Works on disconnected graphs by
coloring each component.

Time complexity: O(V + E). Space: O(V).

Returns (True, (side_A, side_B)) on success, (False, None) on failure.
"""

from typing import Dict, List, Optional, Set, Tuple

ALGO_28_VERSION = "algo-28.v1"

_STDLIB_USED = {"typing", "ast", "pathlib"}


def is_bipartite(graph: Dict) -> Tuple[bool, Optional[Tuple[Set, Set]]]:
    """Return (is_bipartite, partition) for undirected ``graph``.

    ``partition`` is (side_0, side_1), two disjoint sets covering all nodes
    (neighbor-only nodes included), or None if the graph is not bipartite.
    """
    color: Dict = {}
    side: List[Set] = [set(), set()]
    nodes = list(graph)
    for nbrs in graph.values():
        for nb in nbrs:
            if nb not in graph and nb not in nodes:
                nodes.append(nb)
    for start in nodes:
        if start in color:
            continue
        color[start] = 0
        side[0].add(start)
        queue = [start]
        while queue:
            u = queue.pop(0)
            for v in graph.get(u, []):
                if v not in color:
                    color[v] = 1 - color[u]
                    side[color[v]].add(v)
                    queue.append(v)
                elif color[v] == color[u]:
                    return False, None
    return True, (side[0], side[1])


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
    square = {"A": ["B", "D"], "B": ["A", "C"], "C": ["B", "D"], "D": ["A", "C"]}
    ok, part = is_bipartite(square)
    assert ok is True
    assert part[0] | part[1] == {"A", "B", "C", "D"}
    assert part[0] & part[1] == set()
    ok2, part2 = is_bipartite({"A": ["B", "C"], "B": ["A", "C"], "C": ["A", "B"]})
    assert ok2 is False and part2 is None  # triangle: odd cycle
    ok3, part3 = is_bipartite({})
    assert ok3 is True and part3 == (set(), set())
    ok4, part4 = is_bipartite({"A": ["B"], "B": ["A"], "C": ["D"], "D": ["C"]})
    assert ok4 is True and part4[0] | part4[1] == {"A", "B", "C", "D"}
    ok5, _ = is_bipartite({"L": ["L"]})  # self-loop is never bipartite
    assert ok5 is False
    assert stdlib_only() is True
    print("algo_28 OK")


if __name__ == "__main__":
    main()
