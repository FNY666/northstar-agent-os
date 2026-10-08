"""Min-cost max-flow successive shortest path (FLOW-011), Real."""
from __future__ import annotations
import ast

VERSION = "flow-11.v1"

def min_cost_flow(n, edges, s, t, maxf):
    import heapq
    g = [[] for _ in range(n)]
    def add_edge(u, v, cap, cost):
        g[u].append([v, cap, cost, len(g[v])])
        g[v].append([u, 0, -cost, len(g[u]) - 1])
    for u, v, cap, cost in edges:
        if u != v and cap > 0:
            add_edge(u, v, cap, cost)
    INF = 10 ** 18
    res = 0
    h = [0] * n
    flow = 0
    while flow < maxf:
        dist = [INF] * n
        dist[s] = 0
        prevv = [0] * n
        preve = [0] * n
        pq = [(0, s)]
        while pq:
            d, v = heapq.heappop(pq)
            if dist[v] < d:
                continue
            for i, e in enumerate(g[v]):
                to, cap, cost, _ = e
                if cap > 0 and dist[to] > dist[v] + cost + h[v] - h[to]:
                    dist[to] = dist[v] + cost + h[v] - h[to]
                    prevv[to] = v
                    preve[to] = i
                    heapq.heappush(pq, (dist[to], to))
        if dist[t] == INF:
            break
        for v in range(n):
            if dist[v] < INF:
                h[v] += dist[v]
        d = maxf - flow
        v = t
        while v != s:
            d = min(d, g[prevv[v]][preve[v]][1])
            v = prevv[v]
        flow += d
        res += d * h[t]
        v = t
        while v != s:
            e = g[prevv[v]][preve[v]]
            e[1] -= d
            g[v][e[3]][1] += d
            v = prevv[v]
    return flow, res

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
    f, c = min_cost_flow(4, [(0,1,2,1),(0,2,2,2),(1,3,2,1),(2,3,2,1)], 0, 3, 4)
    assert (f, c) == (4, 10)
    f, c = min_cost_flow(2, [(0,1,3,2)], 0, 1, 5)
    assert (f, c) == (3, 6)
    f, c = min_cost_flow(3, [(0,1,1,1)], 0, 2, 5)
    assert (f, c) == (0, 0)
    assert stdlib_only()
    print("flow-11 OK")


if __name__ == "__main__":
    main()
