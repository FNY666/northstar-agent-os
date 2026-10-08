"""Ugly Number II: n-th number whose prime factors are only 2, 3, 5 IS: min-heap generating multiples in order IS NOT: trial division of every integer"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-24.v1"

def _req_n(n):
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    return n


def nth_ugly_number(n):
    """Return the n-th ugly number (1-based).

    Fail-closed: ``n`` must be a positive int, else :class:`ValueError`.
    """
    n = _req_n(n)
    heap = [1]
    seen = {1}
    val = 1
    for _ in range(n):
        val = heapq.heappop(heap)
        for f in (2, 3, 5):
            nxt = val * f
            if nxt not in seen:
                seen.add(nxt)
                heapq.heappush(heap, nxt)
    return val

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
    assert nth_ugly_number(10) == 12
    assert nth_ugly_number(1) == 1
    assert nth_ugly_number(7) == 8
    assert nth_ugly_number(11) == 15
    try:
        nth_ugly_number(0)
    except ValueError:
        pass
    else:
        raise AssertionError("n=0 must raise ValueError")
    assert stdlib_only()
    print("heap-24.v1 OK")


if __name__ == "__main__":
    main()
