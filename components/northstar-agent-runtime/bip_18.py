"""Bipartite girth.

What this IS: length of the shortest cycle via BFS from each vertex, fail-closed on bad input
What this IS NOT: a heuristic; BFS-from-each-vertex is exact for unweighted graphs
"""

from __future__ import annotations

import ast

#: Module version.
BIP_18_VERSION = "bip-girth.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-girth.v1"


class BipError(Exception):
    """Fail-closed."""



def girth(n: int, edges: list):
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
        adj[u].append(v)
        adj[v].append(u)
    from collections import deque
    best = None
    for s in range(n):
        dist = [-1] * n
        par = [-1] * n
        dist[s] = 0
        q = deque([s])
        while q:
            u = q.popleft()
            for w in adj[u]:
                if dist[w] == -1:
                    dist[w] = dist[u] + 1
                    par[w] = u
                    q.append(w)
                elif par[u] != w and par[w] != u:
                    cyc = dist[u] + dist[w] + 1
                    if best is None or cyc < best:
                        best = cyc
    return best


def test_girth_square():
    assert girth(4, [(0, 1), (1, 2), (2, 3), (3, 0)]) == 4


def test_girth_k23():
    assert girth(5, [(a, b) for a in range(2) for b in range(2, 5)]) == 4


def test_girth_tree():
    assert girth(4, [(0, 1), (1, 2), (2, 3)]) is None


def test_girth_bad():
    try:
        girth(2, [(0, 5)])
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
    test_girth_square()
    test_girth_k23()
    test_girth_tree()
    test_girth_bad()
    assert stdlib_only()
    print("bip-18 OK: girth")


if __name__ == "__main__":
    main()
