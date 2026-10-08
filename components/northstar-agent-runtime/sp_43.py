"""Path with maximum probability (SP-043), Real."""
from __future__ import annotations
import ast

VERSION = "sp-43.v1"

import heapq

def max_probability(n, edges, probs, src, dst):
    adj = [[] for _ in range(n)]
    for (u, v), p in zip(edges, probs):
        adj[u].append((v, p))
        adj[v].append((u, p))
    best = [0.0] * n
    best[src] = 1.0
    pq = [(-1.0, src)]
    while pq:
        nb, u = heapq.heappop(pq)
        nb = -nb
        if nb < best[u] - 1e-12:
            continue
        for v, p in adj[u]:
            cand = nb * p
            if cand > best[v] + 1e-12:
                best[v] = cand
                heapq.heappush(pq, (-cand, v))
    return best[dst]

def main() -> None:
    e = [(0, 1), (1, 2), (0, 2)]
    assert abs(max_probability(3, e, [0.5, 0.5, 0.2], 0, 2) - 0.25) < 1e-9
    assert abs(max_probability(3, e, [0.5, 0.5, 0.9], 0, 2) - 0.9) < 1e-9
    assert max_probability(3, [(0, 1)], [0.5], 0, 2) == 0.0
    assert max_probability(1, [], [], 0, 0) == 1.0
    assert stdlib_only()
    print("sp-43 OK")

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


if __name__ == "__main__":
    main()
