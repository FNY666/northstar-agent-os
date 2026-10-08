"""Minimum Cost to Connect Sticks: minimum cost to connect all sticks IS: always connect the two shortest sticks via a min-heap IS NOT: trying all connection orders"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-11.v1"

def _req_sticks(value):
    if not isinstance(value, list):
        raise ValueError("sticks must be a list")
    for i, x in enumerate(value):
        if isinstance(x, bool) or not isinstance(x, (int, float)) or x <= 0:
            raise ValueError(f"sticks[{i}] must be a positive number")
    return list(value)


def connect_sticks(sticks):
    """Return the minimum total cost to connect all sticks.

    Fail-closed: sticks must be a list of positive numbers,
    else :class:`ValueError`.
    """
    sticks = _req_sticks(sticks)
    heap = list(sticks)
    heapq.heapify(heap)
    cost = 0
    while len(heap) > 1:
        a = heapq.heappop(heap)
        b = heapq.heappop(heap)
        cost += a + b
        heapq.heappush(heap, a + b)
    return cost

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
    assert connect_sticks([2, 4, 3]) == 14
    assert connect_sticks([1, 8, 3, 5]) == 30
    assert connect_sticks([]) == 0
    assert connect_sticks([5]) == 0
    try:
        connect_sticks([1, -2])
    except ValueError:
        pass
    else:
        raise AssertionError("non-positive stick must raise ValueError")
    assert stdlib_only()
    print("heap-11.v1 OK")


if __name__ == "__main__":
    main()
