"""Odd cycle witness extraction.

What this IS: returns an odd cycle when the graph is not bipartite, else None, fail-closed on bad input
What this IS NOT: bipartiteness alone; the witness is an explicit odd cycle
"""

from __future__ import annotations

import ast

#: Module version.
BIP_23_VERSION = "bip-odd-cycle.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-odd-cycle.v1"


class BipError(Exception):
    """Fail-closed."""



def odd_cycle_witness(n: int, edges: list):
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
        adj[u].append(v)
        adj[v].append(u)
    color = {}
    parent = {}
    for s in range(n):
        if s in color:
            continue
        color[s] = 0
        parent[s] = -1
        stack = [s]
        while stack:
            u = stack.pop()
            for w in adj[u]:
                if w not in color:
                    color[w] = 1 - color[u]
                    parent[w] = u
                    stack.append(w)
                elif color[w] == color[u]:
                    # reconstruct cycle u -> ... -> w -> u
                    a, b = u, w
                    pa, pb = [a], [b]
                    while parent[a] != -1:
                        a = parent[a]
                        pa.append(a)
                    while parent[b] != -1:
                        b = parent[b]
                        pb.append(b)
                    # find LCA
                    sa = set(pa)
                    lca = next(x for x in pb if x in sa)
                    cyc = pa[:pa.index(lca) + 1] + pb[:pb.index(lca)][::-1]
                    if len(cyc) % 2 == 1:
                        return cyc
    return None


def test_witness_triangle():
    c = odd_cycle_witness(3, [(0, 1), (1, 2), (2, 0)])
    assert c is not None and len(c) % 2 == 1


def test_witness_none():
    assert odd_cycle_witness(4, [(0, 1), (1, 2), (2, 3), (3, 0)]) is None


def test_witness_pentagon():
    c = odd_cycle_witness(5, [(i, (i + 1) % 5) for i in range(5)])
    assert c is not None and len(c) == 5


def test_witness_bad():
    try:
        odd_cycle_witness(2, [(0, 8)])
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
    test_witness_triangle()
    test_witness_none()
    test_witness_pentagon()
    test_witness_bad()
    assert stdlib_only()
    print("bip-23 OK: odd cycle witness")


if __name__ == "__main__":
    main()
