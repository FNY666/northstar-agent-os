"""graph_28: 2-SAT via implication graph + SCC. Standard library only.

GRAPH_28_VERSION = graph-28.v1
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

GRAPH_28_VERSION = "graph-28.v1"

# literal: positive int i means x_i, negative means ~x_i. Variables 1..n.


def _node(lit: int, n: int) -> int:
    # x_i -> 2*(i-1), ~x_i -> 2*(i-1)+1
    i = abs(lit) - 1
    return 2 * i + (1 if lit < 0 else 0)


def _neg(node: int) -> int:
    return node ^ 1


def two_sat(n: int, clauses: List[Tuple[int, int]]) -> Optional[List[bool]]:
    """Solve 2-SAT. Returns assignment (index 0..n-1) or None if unsatisfiable."""
    N = 2 * n
    g: Dict[int, List[int]] = {i: [] for i in range(N)}
    gr: Dict[int, List[int]] = {i: [] for i in range(N)}
    for a, b in clauses:
        na, nb = _node(a, n), _node(b, n)
        for u, v in ((_neg(na), nb), (_neg(nb), na)):
            g[u].append(v)
            gr[v].append(u)
    # Kosaraju
    visited = [False] * N
    order: List[int] = []

    def dfs1(u: int) -> None:
        visited[u] = True
        for v in g[u]:
            if not visited[v]:
                dfs1(v)
        order.append(u)

    for u in range(N):
        if not visited[u]:
            dfs1(u)
    comp = [-1] * N

    def dfs2(u: int, c: int) -> None:
        comp[u] = c
        for v in gr[u]:
            if comp[v] == -1:
                dfs2(v, c)

    c = 0
    for u in reversed(order):
        if comp[u] == -1:
            dfs2(u, c)
            c += 1
    assign = [False] * n
    for i in range(n):
        if comp[2 * i] == comp[2 * i + 1]:
            return None
        assign[i] = comp[2 * i] > comp[2 * i + 1]
    return assign


def _check(n: int, clauses: List[Tuple[int, int]], assign: List[bool]) -> bool:
    def val(lit: int) -> bool:
        v = assign[abs(lit) - 1]
        return (not v) if lit < 0 else v
    return all(val(a) or val(b) for a, b in clauses)


def test_two_sat_basic():
    # (x1 | x2) & (~x1 | x2) & (x1 | ~x2)  => x1=T, x2=T
    clauses = [(1, 2), (-1, 2), (1, -2)]
    a = two_sat(2, clauses)
    assert a is not None and _check(2, clauses, a)


def test_two_sat_unsat():
    clauses = [(1, 1), (-1, -1)]
    assert two_sat(1, clauses) is None


def test_two_sat_xor_like():
    # (x1 | x2) & (~x1 | ~x2): satisfiable
    clauses = [(1, 2), (-1, -2)]
    a = two_sat(2, clauses)
    assert a is not None and _check(2, clauses, a)


def test_two_sat_chain():
    # x1 -> x2 -> x3 (as clauses) with x1 forced true
    clauses = [(1, 1), (-1, 2), (-2, 3)]
    a = two_sat(3, clauses)
    assert a is not None and a == [True, True, True]


def test_two_sat_empty():
    assert two_sat(3, []) == [False, False, False]


def main() -> None:
    test_two_sat_basic()
    test_two_sat_unsat()
    test_two_sat_xor_like()
    test_two_sat_chain()
    test_two_sat_empty()
    print("graph_28 (2-SAT) OK")


if __name__ == "__main__":
    main()
