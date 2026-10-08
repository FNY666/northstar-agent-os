"""Bipartite BFS layers.

What this IS: BFS layering from a source; even layers stay on the source side in bipartite graphs
What this IS NOT: Dijkstra; unweighted BFS layers are exact
"""

from __future__ import annotations

import ast

#: Module version.
BIP_15_VERSION = "bip-bfs-layers.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-bfs-layers.v1"


class BipError(Exception):
    """Fail-closed."""



def bfs_layers(n: int, edges: list, src: int) -> list:
    if not (0 <= src < n):
        raise BipError("source out of range")
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
        adj[u].append(v)
        adj[v].append(u)
    from collections import deque
    dist = [-1] * n
    dist[src] = 0
    q = deque([src])
    while q:
        u = q.popleft()
        for w in adj[u]:
            if dist[w] == -1:
                dist[w] = dist[u] + 1
                q.append(w)
    return dist


def test_layers_path():
    assert bfs_layers(4, [(0, 1), (1, 2), (2, 3)], 0) == [0, 1, 2, 3]


def test_layers_disconnected():
    assert bfs_layers(3, [(0, 1)], 0) == [0, 1, -1]


def test_layers_parity():
    d = bfs_layers(4, [(0, 1), (1, 2), (2, 3), (3, 0)], 0)
    assert d[0] % 2 == 0 and d[2] % 2 == 0 and d[1] % 2 == 1


def test_layers_bad_src():
    try:
        bfs_layers(2, [], 9)
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
    test_layers_path()
    test_layers_disconnected()
    test_layers_parity()
    test_layers_bad_src()
    assert stdlib_only()
    print("bip-15 OK: BFS layers")


if __name__ == "__main__":
    main()
