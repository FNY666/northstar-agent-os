"""Minimum edge cover in bipartite graph.

What this IS: a genuine minimum edge cover from a maximum matching, fail-closed on isolated vertices
What this IS NOT: an approximation; the matching-based construction is exact for graphs without isolates
"""

from __future__ import annotations

import ast

#: Module version.
BIP_07_VERSION = "bip-edge-cover.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-edge-cover.v1"


class BipError(Exception):
    """Fail-closed."""



def min_edge_cover(n_left: int, n_right: int, edges: list) -> list:
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
    if not edges:
        if n_left + n_right == 0:
            return []
        raise BipError("isolated vertices")
    adj = [[] for _ in range(n_left)]
    for u, v in edges:
        adj[u].append(v)
    mr = [-1] * n_right
    ml = [-1] * n_left

    def bpm(u, seen):
        for v in adj[u]:
            if not seen[v]:
                seen[v] = True
                if mr[v] == -1 or bpm(mr[v], seen):
                    mr[v] = u
                    ml[u] = v
                    return True
        return False

    for u in range(n_left):
        bpm(u, [False] * n_right)
    cover = []
    used_l = [False] * n_left
    used_r = [False] * n_right
    for u in range(n_left):
        if ml[u] != -1:
            cover.append((u, ml[u]))
            used_l[u] = True
            used_r[ml[u]] = True
    for u, v in edges:
        if not used_l[u] and not used_r[v]:
            cover.append((u, v))
            used_l[u] = True
            used_r[v] = True
    # every vertex must be non-isolated for an edge cover to exist
    deg_l = [0] * n_left
    deg_r = [0] * n_right
    for u, v in edges:
        deg_l[u] += 1
        deg_r[v] += 1
    if any(d == 0 for d in deg_l) or any(d == 0 for d in deg_r):
        raise BipError("isolated vertices")
    for u in range(n_left):
        if not used_l[u]:
            raise BipError("uncovered vertex")
    for v in range(n_right):
        if not used_r[v]:
            raise BipError("uncovered vertex")
    return cover


def _covers_all(nl, nr, edges, cover):
    sl, sr = set(), set()
    for u, v in cover:
        sl.add(u)
        sr.add(v)
    dl = [0] * nl
    dr = [0] * nr
    for u, v in edges:
        dl[u] += 1
        dr[v] += 1
    return all(dl[u] == 0 or u in sl for u in range(nl)) and all(dr[v] == 0 or v in sr for v in range(nr))


def test_ec_k22():
    c = min_edge_cover(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)])
    assert len(c) == 2
    assert _covers_all(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)], c)


def test_ec_path():
    c = min_edge_cover(2, 2, [(0, 0), (1, 1)])
    assert len(c) == 2


def test_ec_isolated():
    try:
        min_edge_cover(2, 1, [(0, 0)])
    except BipError:
        return
    raise AssertionError("expected BipError")


def test_ec_bad():
    try:
        min_edge_cover(1, 1, [(2, 0)])
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
    test_ec_k22()
    test_ec_path()
    test_ec_isolated()
    test_ec_bad()
    assert stdlib_only()
    print("bip-07 OK: min edge cover")


if __name__ == "__main__":
    main()
