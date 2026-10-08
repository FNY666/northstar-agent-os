"""Purdom SCC count.

Returns the number of strongly connected components.

What this IS: a genuine strongly connected components computation, fail-closed on bad input.
What this IS NOT: an approximation; mutual reachability is exact, and the host picks the graph.
"""

from __future__ import annotations

import ast

#: Module version.
SCC_37_VERSION = "scc-purdom-count.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.scc-purdom-count.v1"


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

    def reach(src):
        seen = {src}
        st = [src]
        while st:
            x = st.pop()
            for w in adj[x]:
                if w not in seen:
                    seen.add(w)
                    st.append(w)
        return seen

    R = [reach(v) for v in range(n)]
    comps, used = [], [False] * n
    for v in range(n):
        if used[v]:
            continue
        c = [w for w in range(n) if not used[w] and v in R[w] and w in R[v]]
        for w in c:
            used[w] = True
        comps.append(sorted(c))
    return sorted(comps, key=lambda c: c[0])


def analyze(n: int, edges: list):
    """count view of the SCC decomposition."""
    return len(_sccs(n, edges))


def test_scc_g1():
    assert analyze(8, G1) == 4


def test_scc_dag():
    assert analyze(4, G2) == 4


def test_scc_single():
    assert analyze(1, []) == 1


def test_scc_cycle():
    assert analyze(3, G4) == 1


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
    print("scc-37 OK: Purdom SCC count")


if __name__ == "__main__":
    main()
