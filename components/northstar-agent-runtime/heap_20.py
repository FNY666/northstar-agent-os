"""Network Delay Time: time for a signal from k to reach all nodes IS: min-heap Dijkstra from the source node IS NOT: Floyd-Warshall all-pairs"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-20.v1"

def _req_inputs(times, n, k):
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    if not isinstance(times, list):
        raise ValueError("times must be a list")
    for i, t in enumerate(times):
        if (not isinstance(t, (list, tuple)) or len(t) != 3
                or any(isinstance(v, bool) or not isinstance(v, int) for v in t)):
            raise ValueError(f"times[{i}] must be an int triple")
        if not (1 <= t[0] <= n and 1 <= t[1] <= n) or t[2] < 0:
            raise ValueError(f"times[{i}] out of range")
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= n:
        raise ValueError("k must be a 1-based node index")
    return times, n, k


def network_delay_time(times, n, k):
    """Return the delay for all nodes to receive the signal, else -1.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    times, n, k = _req_inputs(times, n, k)
    adj = [[] for _ in range(n + 1)]
    for u, v, w in times:
        adj[u].append((v, w))
    dist = {k: 0}
    heap = [(0, k)]
    while heap:
        d, u = heapq.heappop(heap)
        if d > dist.get(u, float("inf")):
            continue
        for v, w in adj[u]:
            nd = d + w
            if nd < dist.get(v, float("inf")):
                dist[v] = nd
                heapq.heappush(heap, (nd, v))
    return max(dist.values()) if len(dist) == n else -1

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
    assert network_delay_time([[2, 1, 1], [2, 3, 1], [3, 4, 1]], 4, 2) == 2
    assert network_delay_time([[1, 2, 1]], 2, 2) == -1
    assert network_delay_time([], 1, 1) == 0
    assert network_delay_time([[1, 2, 5], [1, 3, 2]], 3, 1) == 5
    try:
        network_delay_time([[1, 2, 1]], 2, 3)
    except ValueError:
        pass
    else:
        raise AssertionError("k out of range must raise ValueError")
    assert stdlib_only()
    print("heap-20.v1 OK")


if __name__ == "__main__":
    main()
