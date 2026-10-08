"""Preflow FIFO relabel variant (FLOW-044), Real."""
from __future__ import annotations
import ast

VERSION = "flow-44.v1"

def max_flow(n, edges, s, t):
    from collections import deque
    cap = [[0] * n for _ in range(n)]
    for u, v, c in edges:
        if u != v and c > 0:
            cap[u][v] += c
    h = [0] * n
    h[s] = n
    exc = [0] * n
    into_t = [0]
    for v in range(n):
        if cap[s][v] > 0:
            f = cap[s][v]
            cap[s][v] = 0
            cap[v][s] += f
            exc[v] += f
            exc[s] -= f
            if v == t:
                into_t[0] += f
    def push(u):
        for v in range(n):
            if cap[u][v] > 0 and h[u] == h[v] + 1:
                d = min(exc[u], cap[u][v])
                cap[u][v] -= d
                cap[v][u] += d
                exc[u] -= d
                exc[v] += d
                if v == t:
                    into_t[0] += d
                return True
        return False
    def relabel(u):
        best = None
        for v in range(n):
            if cap[u][v] > 0 and (best is None or h[v] < best):
                best = h[v]
        if best is not None:
            h[u] = best + 1
    active = deque([v for v in range(n) if v != s and v != t and exc[v] > 0])
    inq = set(active)
    while active:
        u = active.popleft()
        inq.discard(u)
        while exc[u] > 0:
            if not push(u):
                relabel(u)
        for v in range(n):
            if v != s and v != t and exc[v] > 0 and v not in inq:
                active.append(v)
                inq.add(v)
    return into_t[0]

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections",
               "math", "itertools", "functools", "random", "sys", "copy"}
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
    g1 = [(0,1,16),(0,2,13),(1,2,10),(1,3,12),(2,1,4),(2,4,14),(3,2,9),(3,5,20),(4,3,7),(4,5,4)]
    assert max_flow(6, g1, 0, 5) == 23
    assert max_flow(4, [(0,1,3),(0,2,3),(1,3,3),(2,3,3)], 0, 3) == 6
    assert max_flow(2, [(0,1,7)], 0, 1) == 7
    assert max_flow(3, [(0,1,5)], 0, 2) == 0
    assert stdlib_only()
    print("flow-44 OK")


if __name__ == "__main__":
    main()
