"""Bipartite redundancy (shared neighbor pairs).

What this IS: counts left-vertex pairs sharing at least one right neighbor, fail-closed
What this IS NOT: a heuristic; exact pair counting
"""

from __future__ import annotations

import ast

#: Module version.
BIP_50_VERSION = "bip-redundancy.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-redundancy.v1"


class BipError(Exception):
    """Fail-closed."""



def redundancy_pairs(n_left: int, n_right: int, edges: list) -> int:
    nbr = [set() for _ in range(n_left)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        nbr[u].add(v)
    count = 0
    for a in range(n_left):
        for b in range(a + 1, n_left):
            if nbr[a] & nbr[b]:
                count += 1
    return count


def test_red_k22():
    assert redundancy_pairs(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)]) == 1


def test_red_none():
    assert redundancy_pairs(3, 3, [(0, 0), (1, 1), (2, 2)]) == 0


def test_red_chain():
    assert redundancy_pairs(3, 2, [(0, 0), (1, 0), (1, 1), (2, 1)]) == 2


def test_red_bad():
    try:
        redundancy_pairs(1, 1, [(2, 0)])
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
    test_red_k22()
    test_red_none()
    test_red_chain()
    test_red_bad()
    assert stdlib_only()
    print("bip-50 OK: redundancy")


if __name__ == "__main__":
    main()
