"""Cheapest Flights Within K Stops: cheapest price from src to dst with at most k stops IS: min-heap Dijkstra over (cost, node, stops) IS NOT: Bellman-Ford relaxation"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-19.v1"

def _req_inputs(n, flights, src, dst, k):
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    if not isinstance(flights, list):
        raise ValueError("flights must be a list")
    for i, f in enumerate(flights):
        if (not isinstance(f, (list, tuple)) or len(f) != 3
                or any(isinstance(v, bool) or not isinstance(v, int) for v in f)):
            raise ValueError(f"flights[{i}] must be an int triple")
        if not (0 <= f[0] < n and 0 <= f[1] < n) or f[2] < 0:
            raise ValueError(f"flights[{i}] out of range")
    for name, v in (("src", src), ("dst", dst)):
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < n:
            raise ValueError(f"{name} must be a node index")
    if isinstance(k, bool) or not isinstance(k, int) or k < 0:
        raise ValueError("k must be a non-negative int")
    return n, flights, src, dst, k


def cheapest_flights(n, flights, src, dst, k):
    """Return the cheapest price with at most ``k`` stops, else -1.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    n, flights, src, dst, k = _req_inputs(n, flights, src, dst, k)
    adj = [[] for _ in range(n)]
    for u, v, w in flights:
        adj[u].append((v, w))
    heap = [(0, src, 0)]
    seen = {}
    while heap:
        cost, u, stops = heapq.heappop(heap)
        if u == dst:
            return cost
        if stops > k or seen.get((u, stops), float("inf")) <= cost:
            continue
        seen[(u, stops)] = cost
        for v, w in adj[u]:
            heapq.heappush(heap, (cost + w, v, stops + 1))
    return -1

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
    flights = [[0, 1, 100], [1, 2, 100], [0, 2, 500]]
    assert cheapest_flights(3, flights, 0, 2, 1) == 200
    assert cheapest_flights(3, flights, 0, 2, 0) == 500
    assert cheapest_flights(3, [[0, 1, 100]], 0, 2, 1) == -1
    assert cheapest_flights(2, [[0, 1, 50]], 0, 0, 0) == 0
    try:
        cheapest_flights(0, [], 0, 0, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("n=0 must raise ValueError")
    assert stdlib_only()
    print("heap-19.v1 OK")


if __name__ == "__main__":
    main()
