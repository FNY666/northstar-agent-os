"""Kosaraju iterative condensation DAG.

Returns the condensation DAG as a sorted adjacency list.

What this IS: a genuine strongly connected components computation, fail-closed on bad input.
What this IS NOT: an approximation; mutual reachability is exact, and the host picks the graph.
"""

from __future__ import annotations

import ast

#: Module version.
SCC_28_VERSION = "scc-kosaraju-iter-condensation.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.scc-kosaraju-iter-condensation.v1"


class SCCError(Exception):
    """Fail-closed."""


G1 = [(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 3), (5, 6), (6, 5), (7, 7)]
G2 = [(0, 1), (0, 2), (1, 3), (2, 3)]
G4 = [(0, 1), (1, 2), (2, 0)]


def _sccs(n: int, edges: list) -> list:
    adj = [[] for _ in range(n)]
    radj = [[] for _ in range(n)]
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise SCCError("edge out of range")
        adj[u].append(v)
        radj[v].append(u)
    vis, order = [False] * n, []
    for s in range(n):
        if vis[s]:
            continue
        vis[s] = True
        stack = [(s, 0)]
        while stack:
            v, i = stack[-1]
            if i < len(adj[v]):
                w = adj[v][i]
                stack[-1] = (v, i + 1)
                if not vis[w]:
                    vis[w] = True
                    stack.append((w, 0))
            else:
                stack.pop()
                order.append(v)
    cid, comps = [-1] * n, []
    for v in reversed(order):
        if cid[v] != -1:
            continue
        cid[v] = len(comps)
        st, c = [v], []
        while st:
            x = st.pop()
            c.append(x)
            for w in radj[x]:
                if cid[w] == -1:
                    cid[w] = len(comps)
                    st.append(w)
        comps.append(sorted(c))
    return sorted(comps, key=lambda c: c[0])


def analyze(n: int, edges: list):
    """condensation view of the SCC decomposition."""
    comps = _sccs(n, edges)
    cid = {}
    for i, c in enumerate(comps):
        for v in c:
            cid[v] = i
    dag = [set() for _ in comps]
    for u, v in edges:
        a, b = cid[u], cid[v]
        if a != b:
            dag[a].add(b)
    return [sorted(s) for s in dag]


def test_scc_g1():
    assert analyze(8, G1) == [[1], [], [], []]


def test_scc_dag():
    assert analyze(4, G2) == [[1, 2], [3], [3], []]


def test_scc_single():
    assert analyze(3, G4) == [[]]


def test_scc_cycle():
    assert analyze(1, []) == [[]]


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
    print("scc-28 OK: Kosaraju iterative condensation DAG")


if __name__ == "__main__":
    main()
