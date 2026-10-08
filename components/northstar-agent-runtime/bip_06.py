"""Maximum independent set in bipartite graph.

What this IS: a genuine maximum independent set via complement of Konig vertex cover, fail-closed
What this IS NOT: a heuristic; the Konig complement is exact for bipartite graphs
"""

from __future__ import annotations

import ast

#: Module version.
BIP_06_VERSION = "bip-bip-independent.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-bip-independent.v1"


class BipError(Exception):
    """Fail-closed."""



def _mvc(nl, nr, edges):
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
    ml = [-1] * nl
    for v, u in enumerate(mr):
        if u != -1:
            ml[u] = v
    from collections import deque
    sl = [False] * nl
    sr = [False] * nr
    q = deque([u for u in range(nl) if ml[u] == -1])
    for u in list(q):
        sl[u] = True
    while q:
        u = q.popleft()
        for v in adj[u]:
            if ml[u] == v or sr[v]:
                continue
            sr[v] = True
            w = mr[v]
            if w != -1 and not sl[w]:
                sl[w] = True
                q.append(w)
    return [u for u in range(nl) if not sl[u]], [v for v in range(nr) if sr[v]]


def max_independent_set(n_left: int, n_right: int, edges: list) -> tuple:
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
    cl, cr = _mvc(n_left, n_right, edges)
    return ([u for u in range(n_left) if u not in set(cl)],
            [v for v in range(n_right) if v not in set(cr)])


def test_mis_k22():
    il, ir = max_independent_set(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)])
    assert len(il) + len(ir) == 2


def test_mis_empty():
    il, ir = max_independent_set(2, 3, [])
    assert (il, ir) == ([0, 1], [0, 1, 2])


def test_mis_star():
    il, ir = max_independent_set(1, 3, [(0, 0), (0, 1), (0, 2)])
    assert len(il) + len(ir) == 3


def test_mis_bad():
    try:
        max_independent_set(2, 2, [(0, 9)])
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
    test_mis_k22()
    test_mis_empty()
    test_mis_star()
    test_mis_bad()
    assert stdlib_only()
    print("bip-06 OK: bipartite max independent set")


if __name__ == "__main__":
    main()
