"""Minimum Cost to Hire K Workers: minimum cost to hire k workers at fair wages IS: sort by wage/quality ratio, max-heap of qualities IS NOT: trying every worker subset"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-29.v1"

def _req_inputs(quality, wage, k):
    if not isinstance(quality, list) or not isinstance(wage, list):
        raise ValueError("quality and wage must be lists")
    if not quality or len(quality) != len(wage):
        raise ValueError("quality and wage must be non-empty and equal length")
    for name, v in (("quality", quality), ("wage", wage)):
        for i, x in enumerate(v):
            if isinstance(x, bool) or not isinstance(x, (int, float)) or x <= 0:
                raise ValueError(f"{name}[{i}] must be positive")
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= len(quality):
        raise ValueError("k must satisfy 1 <= k <= len(quality)")
    return list(quality), list(wage), k


def mincost_to_hire_workers(quality, wage, k):
    """Return the minimum cost to hire ``k`` workers.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    quality, wage, k = _req_inputs(quality, wage, k)
    order = sorted(range(len(quality)), key=lambda i: wage[i] / quality[i])
    heap = []
    total_q = 0
    best = float("inf")
    for i in order:
        heapq.heappush(heap, -quality[i])
        total_q += quality[i]
        if len(heap) > k:
            total_q += heapq.heappop(heap)
        if len(heap) == k:
            best = min(best, total_q * wage[i] / quality[i])
    return best

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
    got = mincost_to_hire_workers([10, 20, 5], [70, 50, 30], 2)
    assert abs(got - 105.0) < 1e-6, got
    got = mincost_to_hire_workers([3, 1, 10, 10, 1], [4, 8, 2, 2, 7], 3)
    assert abs(got - 30.6666667) < 1e-4, got
    got = mincost_to_hire_workers([5], [10], 1)
    assert abs(got - 10.0) < 1e-9, got
    try:
        mincost_to_hire_workers([1], [1, 2], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("length mismatch must raise ValueError")
    assert stdlib_only()
    print("heap-29.v1 OK")


if __name__ == "__main__":
    main()
