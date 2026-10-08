"""Maximum bipartite matching (Kuhn).

What this IS: a genuine maximum bipartite matching via Kuhn augmenting paths, fail-closed on bad input
What this IS NOT: Hopcroft-Karp; Kuhn is O(VE) but exact
"""

from __future__ import annotations

import ast

#: Module version.
BIP_04_VERSION = "bip-kuhn-matching.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-kuhn-matching.v1"


class BipError(Exception):
    """Fail-closed."""



def max_matching(n_left: int, n_right: int, edges: list) -> dict:
    adj = [[] for _ in range(n_left)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        adj[u].append(v)
    match_r = [-1] * n_right

    def bpm(u, seen):
        for v in adj[u]:
            if seen[v]:
                continue
            seen[v] = True
            if match_r[v] == -1 or bpm(match_r[v], seen):
                match_r[v] = u
                return True
        return False

    size = 0
    for u in range(n_left):
        if bpm(u, [False] * n_right):
            size += 1
    return {v: u for v, u in enumerate(match_r) if u != -1}


def test_kuhn_perfect():
    m = max_matching(2, 2, [(0, 0), (0, 1), (1, 0)])
    assert len(m) == 2


def test_kuhn_partial():
    m = max_matching(3, 2, [(0, 0), (1, 0), (2, 1)])
    assert len(m) == 2


def test_kuhn_empty():
    assert max_matching(2, 2, []) == {}


def test_kuhn_bad():
    try:
        max_matching(2, 2, [(0, 5)])
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
    test_kuhn_perfect()
    test_kuhn_partial()
    test_kuhn_empty()
    test_kuhn_bad()
    assert stdlib_only()
    print("bip-04 OK: Kuhn max matching")


if __name__ == "__main__":
    main()
