"""Path with Maximum Probability: most reliable path between two nodes IS: max-heap Dijkstra over path probabilities IS NOT: enumerating all simple paths"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-21.v1"

def _req_inputs(n, edges, succ_prob, start, end):
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    if not isinstance(edges, list) or not isinstance(succ_prob, list):
        raise ValueError("edges and succ_prob must be lists")
    if len(edges) != len(succ_prob):
        raise ValueError("edges and succ_prob must have equal length")
    for i, e in enumerate(edges):
        if (not isinstance(e, (list, tuple)) or len(e) != 2
                or any(isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < n for v in e)):
            raise ValueError(f"edges[{i}] must be a valid node pair")
    for i, p in enumerate(succ_prob):
        if isinstance(p, bool) or not isinstance(p, (int, float)) or not 0 <= p <= 1:
            raise ValueError(f"succ_prob[{i}] must be in [0, 1]")
    for name, v in (("start", start), ("end", end)):
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < n:
            raise ValueError(f"{name} must be a node index")
    return n, edges, succ_prob, start, end


def max_probability(n, edges, succ_prob, start, end):
    """Return the maximum success probability from start to end.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    n, edges, succ_prob, start, end = _req_inputs(n, edges, succ_prob, start, end)
    adj = [[] for _ in range(n)]
    for (u, v), p in zip(edges, succ_prob):
        adj[u].append((v, p))
        adj[v].append((u, p))
    best = [0.0] * n
    best[start] = 1.0
    heap = [(-1.0, start)]
    while heap:
        neg_p, u = heapq.heappop(heap)
        p = -neg_p
        if u == end:
            return p
        if p < best[u]:
            continue
        for v, w in adj[u]:
            np = p * w
            if np > best[v]:
                best[v] = np
                heapq.heappush(heap, (-np, v))
    return 0.0

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert max_probability(3, [[0, 1], [1, 2], [0, 2]], [0.5, 0.5, 0.2], 0, 2) == 0.25
    assert max_probability(3, [[0, 1]], [0.5], 0, 2) == 0.0
    assert max_probability(1, [], [], 0, 0) == 1.0
    got = max_probability(3, [[0, 1], [1, 2], [0, 2]], [0.5, 0.5, 0.3], 0, 2)
    assert abs(got - 0.3) < 1e-9, got
    try:
        max_probability(2, [[0, 1]], [1.5], 0, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("prob > 1 must raise ValueError")
    assert stdlib_only()
    print("heap-21.v1 OK")


if __name__ == "__main__":
    main()
