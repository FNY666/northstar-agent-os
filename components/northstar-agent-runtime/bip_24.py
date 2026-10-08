"""Bipartite radius and center.

What this IS: exact radius and center vertices via all-pairs BFS, fail-closed on disconnected
What this IS NOT: an approximation; all-pairs BFS is exact unweighted
"""

from __future__ import annotations

import ast

#: Module version.
BIP_24_VERSION = "bip-radius-center.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-radius-center.v1"


class BipError(Exception):
    """Fail-closed."""



def radius_center(n: int, edges: list) -> tuple:
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
        while q:
            u = q.popleft()
            for w in adj[u]:
                if dist[w] == -1:
                    dist[w] = dist[u] + 1
                    q.append(w)
        if any(d == -1 for d in dist):
            raise BipError("disconnected")
        return max(dist)

    eccs = [ecc(s) for s in range(n)]
    r = min(eccs)
    return r, [s for s, e in enumerate(eccs) if e == r]


def test_rc_path():
    r, c = radius_center(4, [(0, 1), (1, 2), (2, 3)])
    assert r == 2 and set(c) == {1, 2}


def test_rc_star():
    r, c = radius_center(4, [(0, 1), (0, 2), (0, 3)])
    assert r == 1 and c == [0]


def test_rc_single():
    assert radius_center(1, []) == (0, [0])


def test_rc_disconnected():
    try:
        radius_center(3, [(0, 1)])
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
    test_rc_path()
    test_rc_star()
    test_rc_single()
    test_rc_disconnected()
    assert stdlib_only()
    print("bip-24 OK: radius and center")


if __name__ == "__main__":
    main()
