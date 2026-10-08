"""Bipartite connected components.

What this IS: connected components of the underlying undirected graph, fail-closed on bad input
What this IS NOT: strong connectivity; components here are weak/underlying
"""

from __future__ import annotations

import ast

#: Module version.
BIP_16_VERSION = "bip-components.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-components.v1"


class BipError(Exception):
    """Fail-closed."""



def components(n: int, edges: list) -> list:
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
        adj[u].append(v)
        adj[v].append(u)
    seen = [False] * n
    comps = []
    for s in range(n):
        if seen[s]:
            continue
        seen[s] = True
        stack = [s]
        comp = []
        while stack:
            u = stack.pop()
            comp.append(u)
            for w in adj[u]:
                if not seen[w]:
                    seen[w] = True
                    stack.append(w)
        comps.append(sorted(comp))
    return sorted(comps, key=lambda c: c[0])


def test_comp_two():
    assert components(4, [(0, 1), (2, 3)]) == [[0, 1], [2, 3]]


def test_comp_single():
    assert components(3, [(0, 1), (1, 2)]) == [[0, 1, 2]]


def test_comp_isolated():
    assert components(3, []) == [[0], [1], [2]]


def test_comp_bad():
    try:
        components(2, [(0, 2)])
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
    test_comp_two()
    test_comp_single()
    test_comp_isolated()
    test_comp_bad()
    assert stdlib_only()
    print("bip-16 OK: connected components")


if __name__ == "__main__":
    main()
