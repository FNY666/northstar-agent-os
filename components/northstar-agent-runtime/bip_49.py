"""Bipartite clustering coefficient.

What this IS: bipartite clustering via 4-cycles over wedges, fail-closed on bad input
What this IS NOT: triangle clustering; 4-cycle based for bipartite graphs
"""

from __future__ import annotations

import ast

#: Module version.
BIP_49_VERSION = "bip-clustering.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-clustering.v1"


class BipError(Exception):
    """Fail-closed."""



def bipartite_clustering(n_left: int, n_right: int, edges: list) -> float:
    nbr_l = [set() for _ in range(n_left)]
    nbr_r = [set() for _ in range(n_right)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        nbr_l[u].add(v)
        nbr_r[v].add(u)
    closed = 0
    total = 0
    for u in range(n_left):
        vs = sorted(nbr_l[u])
        for i in range(len(vs)):
            for j in range(i + 1, len(vs)):
                common = nbr_r[vs[i]] & nbr_r[vs[j]]
                common.discard(u)
                total += len(common)
                # each common w gives a 4-cycle u-vs[i]-w-vs[j]-u; count closed wedges
                closed += len(common)
    # coefficient = closed 4-paths / all 4-paths centered on left vertices
    paths = 0
    for u in range(n_left):
        vs = sorted(nbr_l[u])
        for i in range(len(vs)):
            for j in range(i + 1, len(vs)):
                paths += max(0, len(nbr_r[vs[i]] | nbr_r[vs[j]]) - 1)
    if paths == 0:
        return 0.0
    return closed / paths


def test_cl_k22():
    assert bipartite_clustering(2, 2, [(0, 0), (0, 1), (1, 0), (1, 1)]) == 1.0


def test_cl_tree():
    assert bipartite_clustering(2, 2, [(0, 0), (1, 1)]) == 0.0


def test_cl_empty():
    assert bipartite_clustering(2, 2, []) == 0.0


def test_cl_bad():
    try:
        bipartite_clustering(1, 1, [(0, 5)])
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
    test_cl_k22()
    test_cl_tree()
    test_cl_empty()
    test_cl_bad()
    assert stdlib_only()
    print("bip-49 OK: clustering")


if __name__ == "__main__":
    main()
