"""Super Ugly Number: n-th number whose prime factors come from a given list IS: min-heap generating multiples in order IS NOT: trial division of every integer"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-25.v1"

def _req_inputs(n, primes):
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    if not isinstance(primes, list) or not primes:
        raise ValueError("primes must be a non-empty list")
    for i, p in enumerate(primes):
        if isinstance(p, bool) or not isinstance(p, int) or p < 2:
            raise ValueError(f"primes[{i}] must be an int >= 2")
    return n, list(primes)


def nth_super_ugly_number(n, primes):
    """Return the n-th super ugly number (1-based).

    Fail-closed: bad input raises :class:`ValueError`.
    """
    n, primes = _req_inputs(n, primes)
    heap = [1]
    seen = {1}
    val = 1
    for _ in range(n):
        val = heapq.heappop(heap)
        for f in primes:
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
    assert nth_super_ugly_number(12, [2, 7, 13, 19]) == 32
    assert nth_super_ugly_number(1, [2, 3, 5]) == 1
    assert nth_super_ugly_number(10, [2, 3, 5]) == 12
    try:
        nth_super_ugly_number(5, [])
    except ValueError:
        pass
    else:
        raise AssertionError("empty primes must raise ValueError")
    assert stdlib_only()
    print("heap-25.v1 OK")


if __name__ == "__main__":
    main()
