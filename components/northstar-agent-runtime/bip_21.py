"""Bipartite Eulerian trail check.

What this IS: checks all vertices have even degree and the graph is connected (ignoring isolates)
What this IS NOT: a heuristic; even-degree plus connectivity is exact for Eulerian circuits
"""

from __future__ import annotations

import ast

#: Module version.
BIP_21_VERSION = "bip-eulerian.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-eulerian.v1"


class BipError(Exception):
    """Fail-closed."""



def has_eulerian_circuit(n: int, edges: list) -> bool:
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise BipError("edge out of range")
        adj[u].append(v)
        adj[v].append(u)
    if any(len(a) % 2 for a in adj):
        return False
    start = next((i for i, a in enumerate(adj) if a), None)
    if start is None:
        return True
    seen = set([start])
    stack = [start]
    while stack:
        u = stack.pop()
        for w in adj[u]:
            if w not in seen:
                seen.add(w)
                stack.append(w)
    return all(not a or i in seen for i, a in enumerate(adj))


def test_euler_square():
    assert has_eulerian_circuit(4, [(0, 1), (1, 2), (2, 3), (3, 0)])


def test_euler_path():
    assert not has_eulerian_circuit(4, [(0, 1), (1, 2), (2, 3)])


def test_euler_empty():
    assert has_eulerian_circuit(3, [])


def test_euler_bad():
    try:
        has_eulerian_circuit(2, [(0, 4)])
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
    test_euler_square()
    test_euler_path()
    test_euler_empty()
    test_euler_bad()
    assert stdlib_only()
    print("bip-21 OK: Eulerian check")


if __name__ == "__main__":
    main()
