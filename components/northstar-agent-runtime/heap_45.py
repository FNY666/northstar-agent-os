"""Construct Target Array With Multiple Sums: decide whether target is reachable from all-ones IS: max-heap reversing the construction modulo the rest IS NOT: forward BFS from all-ones"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-45.v1"

def _req_target(value):
    if not isinstance(value, list) or not value:
        raise ValueError("target must be a non-empty list")
    for i, x in enumerate(value):
        if isinstance(x, bool) or not isinstance(x, int) or x < 1:
            raise ValueError(f"target[{i}] must be a positive int")
    return list(value)


def is_possible(target):
    """Return True iff ``target`` is constructible from all ones.

    Fail-closed: ``target`` must be a non-empty list of positive ints,
    else :class:`ValueError`.
    """
    target = _req_target(target)
    total = sum(target)
    heap = [-x for x in target]
    heapq.heapify(heap)
    while True:
        x = -heapq.heappop(heap)
        total -= x
        if x == 1 or total == 1:
            return True
        if total == 0 or x < total or x % total == 0:
            return False
        x %= total
        total += x
        heapq.heappush(heap, -x)

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
    assert is_possible([9, 3, 5]) is True
    assert is_possible([1, 1, 1, 2]) is False
    assert is_possible([8, 5]) is True
    assert is_possible([1]) is True
    assert is_possible([2]) is False
    try:
        is_possible([1, 0])
    except ValueError:
        pass
    else:
        raise AssertionError("zero must raise ValueError")
    assert stdlib_only()
    print("heap-45.v1 OK")


if __name__ == "__main__":
    main()
