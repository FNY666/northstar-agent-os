"""Bipartite check via BFS coloring.

What this IS: a genuine bipartiteness test using BFS 2-coloring, fail-closed on bad input
What this IS NOT: a heuristic; the coloring is exact
"""

from __future__ import annotations

import ast

#: Module version.
BIP_01_VERSION = "bip-bfs-check.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-bfs-check.v1"


class BipError(Exception):
    """Fail-closed."""



def is_bipartite(n: int, edges: list) -> bool:
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
        if u == v:
            return False
        adj[u].append(v)
        adj[v].append(u)
    color = {}
    for s in range(n):
        if s in color:
            continue
        color[s] = 0
        stack = [s]
        while stack:
            u = stack.pop()
            for w in adj[u]:
                if w not in color:
                    color[w] = 1 - color[u]
                    stack.append(w)
                elif color[w] == color[u]:
                    return False
    return True


def test_bipartite_square():
    assert is_bipartite(4, [(0, 1), (1, 2), (2, 3), (3, 0)])


def test_bipartite_triangle():
    assert not is_bipartite(3, [(0, 1), (1, 2), (2, 0)])


def test_bipartite_empty():
    assert is_bipartite(5, [])


def test_bipartite_selfloop():
    assert not is_bipartite(2, [(0, 0)])


def test_bipartite_bad_edge():
    try:
        is_bipartite(2, [(0, 9)])
    except BipError:
        return
    raise AssertionError("expected BipError")



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "collections", "heapq", "itertools", "functools", "math"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_bipartite_square()
    test_bipartite_triangle()
    test_bipartite_empty()
    test_bipartite_selfloop()
    test_bipartite_bad_edge()
    assert stdlib_only()
    print("bip-01 OK: BFS bipartite check")


if __name__ == "__main__":
    main()
