"""Backtracking: graph coloring (k colors, check/assign).

IS: decide whether an undirected graph is k-colorable and, when it is,
produce one valid assignment (colors 0..k-1, adjacent vertices differ).
Vertices are colored one at a time in a fixed order; a color is tried
only if no already-colored neighbour uses it, so every completed
assignment is valid and every valid assignment is reachable.

IS NOT: computing the chromatic number (that would need repeated
k=1,2,... probes - the caller can do that with this primitive), nor
finding a *minimum*-color coloring in one shot; nor greedy coloring -
this is exact backtracking, exponential worst case.

Self-test harness: run ``python backtrack_20.py``.
"""

from typing import Dict, Hashable, List, Optional

VERSION = "backtrack_20.v1"

_ALLOWED_IMPORTS = frozenset({"typing", "dataclasses", "itertools", "ast"})


def stdlib_only() -> bool:
    """Parse this file with ``ast``; True only if every import comes from the
    allowed stdlib set."""
    import ast

    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=__file__)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                return False
            if (node.module or "").split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


Adjacency = Dict[Hashable, List[Hashable]]


def color_graph(adj: Adjacency, k: int) -> Optional[Dict[Hashable, int]]:
    """Return a valid k-coloring dict, or None if k colors are insufficient."""
    if k <= 0:
        return {} if len(adj) == 0 else None
    vertices = list(adj)
    assignment: Dict[Hashable, int] = {}

    def dfs(i: int) -> bool:
        if i == len(vertices):
            return True
        v = vertices[i]
        for color in range(k):
            if all(assignment.get(nb) != color for nb in adj[v]):
                assignment[v] = color
                if dfs(i + 1):
                    return True
                del assignment[v]
        return False

    return dict(assignment) if dfs(0) else None


def is_valid_coloring(adj: Adjacency, coloring: Optional[Dict[Hashable, int]],
                      k: int) -> bool:
    if coloring is None:
        return False
    if set(coloring) != set(adj):
        return False
    if any(not 0 <= c < k for c in coloring.values()):
        return False
    return all(coloring[a] != coloring[b]
               for a, nbrs in adj.items() for b in nbrs)


def main() -> None:
    # Triangle needs 3 colors; 2 is impossible.
    tri = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    assert color_graph(tri, 2) is None
    c3 = color_graph(tri, 3)
    assert is_valid_coloring(tri, c3, 3), c3
    # 4-cycle is bipartite.
    square = {"a": ["b", "d"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c", "a"]}
    c2 = color_graph(square, 2)
    assert is_valid_coloring(square, c2, 2), c2
    # Single vertex is 1-colorable; empty graph colorable with any k.
    assert is_valid_coloring({"v": []}, color_graph({"v": []}, 1), 1)
    assert color_graph({}, 3) == {}
    # Assignment uses only colors in range.
    assert all(0 <= v < 3 for v in c3.values())
    assert stdlib_only() is True
    print("backtrack_20 OK")


if __name__ == "__main__":
    main()
