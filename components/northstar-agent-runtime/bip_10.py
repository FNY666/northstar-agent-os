"""Complete bipartite graph check.

What this IS: checks whether the graph is exactly K_{a,b} for its partition, fail-closed on bad input
What this IS NOT: a heuristic; the edge-count plus bipartiteness test is exact
"""

from __future__ import annotations

import ast

#: Module version.
BIP_10_VERSION = "bip-complete-bip.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-complete-bip.v1"


class BipError(Exception):
    """Fail-closed."""



def is_complete_bipartite(n: int, edges: list):
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
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
                    return False, None
    left = [v for v, c in color.items() if c == 0]
    right = [v for v, c in color.items() if c == 1]
    eset = set()
    for u, v in edges:
        eset.add((min(u, v), max(u, v)))
    if len(eset) != len(left) * len(right):
        return False, None
    return True, (sorted(left), sorted(right))


def test_k33():
    ok, parts = is_complete_bipartite(6, [(a, b) for a in range(3) for b in range(3, 6)])
    assert ok and parts is not None


def test_not_complete():
    ok, _ = is_complete_bipartite(4, [(0, 2), (0, 3), (1, 2)])
    assert not ok


def test_not_bipartite():
    ok, _ = is_complete_bipartite(3, [(0, 1), (1, 2), (2, 0)])
    assert not ok


def test_bad():
    try:
        is_complete_bipartite(2, [(0, 5)])
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
    test_k33()
    test_not_complete()
    test_not_bipartite()
    test_bad()
    assert stdlib_only()
    print("bip-10 OK: complete bipartite check")


if __name__ == "__main__":
    main()
