"""Bipartite join.

What this IS: adds all cross edges between two bipartite graphs' sides, fail-closed
What this IS NOT: a heuristic; exact complete cross connection
"""

from __future__ import annotations

import ast

#: Module version.
BIP_46_VERSION = "bip-join.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-join.v1"


class BipError(Exception):
    """Fail-closed."""



def bip_join(nl1, nr1, e1, nl2, nr2, e2) -> tuple:
    for u, v in e1:
        if not (0 <= u < nl1 and 0 <= v < nr1):
            raise BipError("edge out of range (g1)")
    for u, v in e2:
        if not (0 <= u < nl2 and 0 <= v < nr2):
            raise BipError("edge out of range (g2)")
    nl, nr = nl1 + nl2, nr1 + nr2
    cross = [(u, v + nr1) for u in range(nl1) for v in range(nr2)]
    cross += [(u + nl1, v) for u in range(nl2) for v in range(nr1)]
    e = sorted(set(e1) | {(u + nl1, v + nr1) for u, v in e2} | set(cross))
    return nl, nr, e


def test_join_basic():
    nl, nr, e = bip_join(1, 1, [], 1, 1, [])
    assert (nl, nr) == (2, 2)
    assert (0, 1) in e and (1, 0) in e


def test_join_keeps():
    nl, nr, e = bip_join(1, 1, [(0, 0)], 1, 1, [(0, 0)])
    assert (0, 0) in e and (1, 1) in e


def test_join_empty():
    nl, nr, e = bip_join(0, 0, [], 0, 0, [])
    assert (nl, nr, e) == (0, 0, [])


def test_join_bad():
    try:
        bip_join(1, 1, [(0, 0)], 1, 1, [(7, 0)])
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
    test_join_basic()
    test_join_keeps()
    test_join_empty()
    test_join_bad()
    assert stdlib_only()
    print("bip-46 OK: join")


if __name__ == "__main__":
    main()
