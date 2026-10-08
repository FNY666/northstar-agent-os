"""Edmonds minimum arborescence (directed, simplified) (MST-042), Simulated."""
from __future__ import annotations
import ast

VERSION = "mst-42.v1"

def edmonds(root, n, edges):
    # Chu-Liu/Edmonds minimum arborescence. Simplified: exact when the
    # minimum-incoming-edge selection is acyclic; cycle contraction is
    # documented as simulated for this module.
    INF = float("inf")
    in_w = [INF] * n
    in_e = [None] * n
    for u, v, w in edges:
        if u == v or v == root:
            continue
        if w < in_w[v]:
            in_w[v] = w
            in_e[v] = (u, v, w)
    for v in range(n):
        if v != root and in_e[v] is None:
            return None
    state = [0] * n
    cycle = None
    for s in range(n):
        if s == root or state[s]:
            continue
        cur = s
        path = []
        while True:
            if cur == root or state[cur] == 2:
                break
            if cur in path:
                cycle = path[path.index(cur):]
                break
            path.append(cur)
            cur = in_e[cur][0]
        for x in path:
            state[x] = 2
        if cycle:
            break
    if cycle is None:
        total = sum(in_w[v] for v in range(n) if v != root)
        return total, [in_e[v] for v in range(n) if v != root]
    total = sum(in_w[v] for v in range(n) if v != root)
    return total, "CYCLE_CONTRACT_SIMULATED"

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True

def main() -> None:
    e = [(0, 1, 1), (0, 2, 5), (1, 2, 1)]
    r = edmonds(0, 3, e)
    assert r[0] == 2 and len(r[1]) == 2
    e2 = [(0, 1, 5), (0, 2, 5), (1, 2, 1), (2, 1, 1)]
    r2 = edmonds(0, 3, e2)
    assert r2[1] == "CYCLE_CONTRACT_SIMULATED"
    assert edmonds(0, 3, [(0, 1, 1)]) is None
    assert stdlib_only()
    print("mst-42 OK")


if __name__ == "__main__":
    main()
