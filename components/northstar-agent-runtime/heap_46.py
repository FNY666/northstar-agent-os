"""Minimize Deviation in Array: minimum possible max-min after allowed operations IS: max-heap shrinking even numbers IS NOT: trying every operation sequence"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-46.v1"

def _req_nums(value):
    if not isinstance(value, list) or not value:
        raise ValueError("nums must be a non-empty list")
    for i, x in enumerate(value):
        if isinstance(x, bool) or not isinstance(x, int) or x < 1:
            raise ValueError(f"nums[{i}] must be a positive int")
    return list(value)


def minimum_deviation(nums):
    """Return the minimum achievable deviation.

    Fail-closed: ``nums`` must be a non-empty list of positive ints,
    else :class:`ValueError`.
    """
    nums = _req_nums(nums)
    heap = []
    min_val = float("inf")
    for x in nums:
        v = x * 2 if x % 2 == 1 else x
        heapq.heappush(heap, -v)
        min_val = min(min_val, v)
    best = -heap[0] - min_val
    while -heap[0] % 2 == 0:
        x = -heapq.heappop(heap) // 2
        min_val = min(min_val, x)
        heapq.heappush(heap, -x)
        best = min(best, -heap[0] - min_val)
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
    assert minimum_deviation([1, 2, 3, 4]) == 1
    assert minimum_deviation([4, 1, 5, 20, 3]) == 3
    assert minimum_deviation([2, 10, 8]) == 3
    assert minimum_deviation([7]) == 0
    try:
        minimum_deviation([1, -2])
    except ValueError:
        pass
    else:
        raise AssertionError("negative must raise ValueError")
    assert stdlib_only()
    print("heap-46.v1 OK")


if __name__ == "__main__":
    main()
