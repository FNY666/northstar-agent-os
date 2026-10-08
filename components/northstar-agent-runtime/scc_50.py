"""Gabow DAG check.

Returns True iff the graph is a DAG (all singleton SCCs, no self-loops).

What this IS: a genuine strongly connected components computation, fail-closed on bad input.
What this IS NOT: an approximation; mutual reachability is exact, and the host picks the graph.
"""

from __future__ import annotations

import ast

#: Module version.
SCC_50_VERSION = "scc-gabow-is-dag.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.scc-gabow-is-dag.v1"


class SCCError(Exception):
    """Fail-closed."""


G1 = [(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 3), (5, 6), (6, 5), (7, 7)]
G2 = [(0, 1), (0, 2), (1, 3), (2, 3)]
G4 = [(0, 1), (1, 2), (2, 0)]


def _sccs(n: int, edges: list) -> list:
    adj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise SCCError("edge out of range")
        adj[u].append(v)
    pre = [-1] * n
    done = [False] * n
    S, P, comps, cnt = [], [], [], [0]
    for root in range(n):
        if pre[root] != -1:
            continue
        work = [(root, 0)]
        while work:
            v, i = work[-1]
            if i == 0:
                pre[v] = cnt[0]
                cnt[0] += 1
                S.append(v)
                P.append(v)
            adv = False
            while i < len(adj[v]):
                w = adj[v][i]
                i += 1
                if pre[w] == -1:
                    work[-1] = (v, i)
                    work.append((w, 0))
                    adv = True
                    break
                elif not done[w]:
                    while pre[P[-1]] > pre[w]:
                        P.pop()
            if adv:
                continue
            work.pop()
            if P and P[-1] == v:
                P.pop()
                c = []
                while True:
                    w = S.pop()
                    done[w] = True
                    c.append(w)
                    if w == v:
                        break
                comps.append(sorted(c))
    return sorted(comps, key=lambda c: c[0])


def analyze(n: int, edges: list):
    """is_dag view of the SCC decomposition."""
    comps = _sccs(n, edges)
    if any(len(c) != 1 for c in comps):
        return False
    return not any(u == v for u, v in edges)


def test_scc_g1():
    assert analyze(8, G1) is False


def test_scc_dag():
    assert analyze(4, G2) is True


def test_scc_single():
    assert analyze(1, []) is True


def test_scc_cycle():
    assert analyze(3, G4) is False


def test_scc_bad_edge():
    try:
        analyze(2, [(0, 5)])
    except SCCError:
        return
    raise AssertionError("expected SCCError")


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_scc_g1()
    test_scc_dag()
    test_scc_single()
    test_scc_cycle()
    test_scc_bad_edge()
    assert stdlib_only()
    print("scc-50 OK: Gabow DAG check")


if __name__ == "__main__":
    main()
