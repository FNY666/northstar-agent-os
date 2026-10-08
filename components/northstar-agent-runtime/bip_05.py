"""Minimum vertex cover via Konig.

What this IS: a genuine minimum vertex cover from a maximum matching (Konig theorem), fail-closed
What this IS NOT: an approximation; Konig is exact for bipartite graphs
"""

from __future__ import annotations

import ast

#: Module version.
BIP_05_VERSION = "bip-konig-cover.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-konig-cover.v1"


class BipError(Exception):
    """Fail-closed."""



def _max_match(nl, nr, edges):
    adj = [[] for _ in range(nl)]
    for u, v in edges:
        adj[u].append(v)
    mr = [-1] * nr

    def bpm(u, seen):
        for v in adj[u]:
            if not seen[v]:
                seen[v] = True
                if mr[v] == -1 or bpm(mr[v], seen):
                    mr[v] = u
                    return True
        return False

    for u in range(nl):
        bpm(u, [False] * nr)
    return mr, adj


def min_vertex_cover(n_left: int, n_right: int, edges: list) -> tuple:
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
    mr, adj = _max_match(n_left, n_right, edges)
    ml = [-1] * n_left
    for v, u in enumerate(mr):
        if u != -1:
            ml[u] = v
    # Konig: Z = vertices reachable from free left vertices via alternating paths
    from collections import deque
    seen_l = [False] * n_left
    seen_r = [False] * n_right
    q = deque([u for u in range(n_left) if ml[u] == -1])
    for u in q:
        seen_l[u] = True
    while q:
        u = q.popleft()
        for v in adj[u]:
            if ml[u] == v or seen_r[v]:
                continue
            seen_r[v] = True
            w = mr[v]
            if w != -1 and not seen_l[w]:
                seen_l[w] = True
                q.append(w)
    cover_l = [u for u in range(n_left) if not seen_l[u]]
    cover_r = [v for v in range(n_right) if seen_r[v]]
    return cover_l, cover_r


def _covers(nl, nr, edges, cl, cr):
    sl, sr = set(cl), set(cr)
    return all(u in sl or v in sr for u, v in edges)


def test_konig_k22():
    cl, cr = min_vertex_cover(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)])
    assert len(cl) + len(cr) == 2
    assert _covers(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)], cl, cr)


def test_konig_star():
    cl, cr = min_vertex_cover(1, 3, [(0, 0), (0, 1), (0, 2)])
    assert len(cl) + len(cr) == 1
    assert _covers(1, 3, [(0, 0), (0, 1), (0, 2)], cl, cr)


def test_konig_empty():
    assert min_vertex_cover(2, 2, []) == ([], [])


def test_konig_bad():
    try:
        min_vertex_cover(2, 2, [(3, 0)])
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
    test_konig_k22()
    test_konig_star()
    test_konig_empty()
    test_konig_bad()
    assert stdlib_only()
    print("bip-05 OK: Konig min vertex cover")


if __name__ == "__main__":
    main()
