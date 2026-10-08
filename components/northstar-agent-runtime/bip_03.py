"""Bipartite partition extraction.

What this IS: extraction of the two color classes for a bipartite graph, fail-closed when not bipartite
What this IS NOT: an approximation; raises BipError on odd cycles
"""

from __future__ import annotations

import ast

#: Module version.
BIP_03_VERSION = "bip-partition.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-partition.v1"


class BipError(Exception):
    """Fail-closed."""



def partition(n: int, edges: list) -> tuple:
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
                    raise BipError("not bipartite")
    left = sorted(v for v, c in color.items() if c == 0)
    right = sorted(v for v, c in color.items() if c == 1)
    return left, right


def test_partition_k22():
    l, r = partition(4, [(0, 2), (0, 3), (1, 2), (1, 3)])
    assert set(l) | set(r) == {0, 1, 2, 3}
    assert not (set(l) & set(r))


def test_partition_path():
    l, r = partition(3, [(0, 1), (1, 2)])
    assert (l, r) == ([0, 2], [1]) or (l, r) == ([1], [0, 2])


def test_partition_not_bipartite():
    try:
        partition(3, [(0, 1), (1, 2), (2, 0)])
    except BipError:
        return
    raise AssertionError("expected BipError")


def test_partition_bad():
    try:
        partition(2, [(0, 7)])
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
    test_partition_k22()
    test_partition_path()
    test_partition_not_bipartite()
    test_partition_bad()
    assert stdlib_only()
    print("bip-03 OK: partition extraction")


if __name__ == "__main__":
    main()
