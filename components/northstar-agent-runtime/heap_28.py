"""Maximum Performance of a Team: maximum performance of a team of at most k engineers IS: sort by efficiency, min-heap of speeds IS NOT: enumerating all teams"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-28.v1"

def _req_inputs(n, speed, efficiency, k):
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    for name, v in (("speed", speed), ("efficiency", efficiency)):
        if not isinstance(v, list) or len(v) != n:
            raise ValueError(f"{name} must be a list of length n")
        for i, x in enumerate(v):
            if isinstance(x, bool) or not isinstance(x, (int, float)) or x <= 0:
                raise ValueError(f"{name}[{i}] must be positive")
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= n:
        raise ValueError("k must satisfy 1 <= k <= n")
    return n, list(speed), list(efficiency), k


def max_performance(n, speed, efficiency, k):
    """Return the maximum team performance mod 1_000_000_007.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    n, speed, efficiency, k = _req_inputs(n, speed, efficiency, k)
    order = sorted(range(n), key=lambda i: efficiency[i], reverse=True)
    heap = []
    total = 0
    best = 0
    for i in order:
        heapq.heappush(heap, speed[i])
        total += speed[i]
        if len(heap) > k:
            total -= heapq.heappop(heap)
        best = max(best, total * efficiency[i])
    return best % 1_000_000_007

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
    assert max_performance(6, [2, 10, 3, 1, 5, 8], [5, 4, 3, 9, 7, 2], 2) == 60
    assert max_performance(6, [2, 10, 3, 1, 5, 8], [5, 4, 3, 9, 7, 2], 3) == 68
    assert max_performance(6, [2, 10, 3, 1, 5, 8], [5, 4, 3, 9, 7, 2], 4) == 72
    assert max_performance(1, [5], [5], 1) == 25
    try:
        max_performance(2, [1], [1, 2], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("length mismatch must raise ValueError")
    assert stdlib_only()
    print("heap-28.v1 OK")


if __name__ == "__main__":
    main()
