"""Prim Fibonacci-heap variant (heapq simulation) (MST-019), Simulated."""
from __future__ import annotations
import ast
import heapq
VERSION = "mst-19.v1"

def prim_fib_mock(n, edges):
    # A Fibonacci heap gives O(1) amortized decrease-key and O(E + V log V)
    # total. Python stdlib has no Fibonacci heap, so this module simulates
    # the variant with heapq (binary heap: O(E log V)) and counts the
    # decrease-key operations a Fibonacci heap would accelerate.
    adj = [[] for _ in range(n)]
    for u, v, w in edges:
        if u == v:
            continue
        adj[u].append((w, v))
        adj[v].append((w, u))
    INF = float("inf")
    key = [INF] * n
    in_mst = [False] * n
    par = [-1] * n
    key[0] = 0
    heap = [(0, 0)]
    decrease_keys = 0
    mst = []
    while heap:
        w, u = heapq.heappop(heap)
        if in_mst[u] or w > key[u]:
            continue
        in_mst[u] = True
        if par[u] != -1:
            mst.append((par[u], u, w))
        for w2, v in adj[u]:
            if not in_mst[v] and w2 < key[v]:
                key[v] = w2
                par[v] = u
                heapq.heappush(heap, (w2, v))
                decrease_keys += 1
    return sum(x[2] for x in mst), mst, decrease_keys

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
    t, m, dk = prim_fib_mock(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)])
    assert t == 3 and len(m) == 2 and dk >= 2
    t, m, dk = prim_fib_mock(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1), (0, 2, 2)])
    assert t == 3
    assert stdlib_only()
    print("mst-19 OK")


if __name__ == "__main__":
    main()
