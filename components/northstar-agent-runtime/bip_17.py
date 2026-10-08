"""Bipartite graph diameter.

What this IS: exact diameter via all-pairs BFS on the underlying undirected graph, fail-closed
What this IS NOT: an approximation; all-pairs BFS is exact for unweighted graphs
"""

from __future__ import annotations

import ast

#: Module version.
BIP_17_VERSION = "bip-diameter.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-diameter.v1"


class BipError(Exception):
    """Fail-closed."""



def diameter(n: int, edges: list) -> int:
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
        adj[u].append(v)
        adj[v].append(u)
    from collections import deque

    def ecc(s):
        dist = [-1] * n
        dist[s] = 0
        q = deque([s])
        far = 0
        while q:
            u = q.popleft()
            for w in adj[u]:
                if dist[w] == -1:
                    dist[w] = dist[u] + 1
                    far = dist[w]
                    q.append(w)
        if any(d == -1 for d in dist):
            raise BipError("disconnected")
        return far

    return max(ecc(s) for s in range(n))


def test_diam_path():
    assert diameter(4, [(0, 1), (1, 2), (2, 3)]) == 3


def test_diam_k22():
    assert diameter(4, [(0, 2), (0, 3), (1, 2), (1, 3)]) == 2


def test_diam_single():
    assert diameter(1, []) == 0


def test_diam_disconnected():
    try:
        diameter(3, [(0, 1)])
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
    test_diam_path()
    test_diam_k22()
    test_diam_single()
    test_diam_disconnected()
    assert stdlib_only()
    print("bip-17 OK: diameter")


if __name__ == "__main__":
    main()
