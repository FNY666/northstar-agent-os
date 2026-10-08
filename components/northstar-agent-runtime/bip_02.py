"""Bipartite check via DFS coloring.

What this IS: a genuine bipartiteness test using iterative DFS 2-coloring, fail-closed on bad input
What this IS NOT: a heuristic; the coloring is exact
"""

from __future__ import annotations

import ast

#: Module version.
BIP_02_VERSION = "bip-dfs-check.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-dfs-check.v1"


class BipError(Exception):
    """Fail-closed."""



def is_bipartite_dfs(n: int, edges: list) -> bool:
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
        if u == v:
            return False
        adj[u].append(v)
        adj[v].append(u)
    color = [-1] * n
    for s in range(n):
        if color[s] != -1:
            continue
        color[s] = 0
        stack = [(s, 0)]
        while stack:
            u, it = stack[-1]
            if it < len(adj[u]):
                w = adj[u][it]
                stack[-1] = (u, it + 1)
                if color[w] == -1:
                    color[w] = 1 - color[u]
                    stack.append((w, 0))
                elif color[w] == color[u]:
                    return False
            else:
                stack.pop()
    return True


def test_dfs_square():
    assert is_bipartite_dfs(4, [(0, 1), (1, 2), (2, 3), (3, 0)])


def test_dfs_odd():
    assert not is_bipartite_dfs(5, [(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)])


def test_dfs_disconnected():
    assert is_bipartite_dfs(6, [(0, 1), (2, 3), (4, 5)])


def test_dfs_bad():
    try:
        is_bipartite_dfs(1, [(0, 1)])
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
    test_dfs_square()
    test_dfs_odd()
    test_dfs_disconnected()
    test_dfs_bad()
    assert stdlib_only()
    print("bip-02 OK: DFS bipartite check")


if __name__ == "__main__":
    main()
