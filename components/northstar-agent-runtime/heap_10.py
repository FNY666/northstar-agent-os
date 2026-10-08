"""IPO: Maximize Capital: pick up to k projects to maximize final capital IS: min-heap by capital requirement plus max-heap by profit IS NOT: trying every subset of projects"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-10.v1"

def _req_inputs(k, w, profits, capital):
    if isinstance(k, bool) or not isinstance(k, int) or k < 0:
        raise ValueError("k must be a non-negative int")
    if isinstance(w, bool) or not isinstance(w, (int, float)) or w < 0:
        raise ValueError("w must be a non-negative number")
    if not isinstance(profits, list) or not isinstance(capital, list):
        raise ValueError("profits and capital must be lists")
    if len(profits) != len(capital):
        raise ValueError("profits and capital must have equal length")
    return k, w, list(profits), list(capital)


def find_maximized_capital(k, w, profits, capital):
    """Return the maximum capital after at most ``k`` projects.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    k, w, profits, capital = _req_inputs(k, w, profits, capital)
    needy = sorted(zip(capital, profits))
    i = 0
    affordable = []
    for _ in range(k):
        while i < len(needy) and needy[i][0] <= w:
            heapq.heappush(affordable, -needy[i][1])
            i += 1
        if not affordable:
            break
        w += -heapq.heappop(affordable)
    return w

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
    assert find_maximized_capital(2, 0, [1, 2, 3], [0, 1, 1]) == 4
    assert find_maximized_capital(3, 0, [1, 2, 3], [0, 1, 2]) == 6
    assert find_maximized_capital(1, 0, [5], [10]) == 0
    assert find_maximized_capital(0, 7, [1], [0]) == 7
    try:
        find_maximized_capital(1, 0, [1], [0, 1])
    except ValueError:
        pass
    else:
        raise AssertionError("length mismatch must raise ValueError")
    assert stdlib_only()
    print("heap-10.v1 OK")


if __name__ == "__main__":
    main()
