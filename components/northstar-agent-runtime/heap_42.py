"""Minimum Operations to Halve Array Sum: fewest halvings to reduce the sum by at least half IS: max-heap always halving the current largest element IS NOT: trying every halving order"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-42.v1"

def _req_nums(value):
    if not isinstance(value, list) or not value:
        raise ValueError("nums must be a non-empty list")
    for i, x in enumerate(value):
        if isinstance(x, bool) or not isinstance(x, (int, float)) or x <= 0:
            raise ValueError(f"nums[{i}] must be positive")
    return [float(x) for x in value]


def halve_array(nums):
    """Return the minimum operations to halve the array sum.

    Fail-closed: ``nums`` must be a non-empty list of positive numbers,
    else :class:`ValueError`.
    """
    nums = _req_nums(nums)
    target = sum(nums) / 2.0
    heap = [-x for x in nums]
    heapq.heapify(heap)
    ops = 0
    while target > 0:
        x = -heapq.heappop(heap) / 2.0
        target -= x
        heapq.heappush(heap, -x)
        ops += 1
    return ops

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
    assert halve_array([5, 19, 8, 1]) == 3
    assert halve_array([3, 8, 20]) == 3
    assert halve_array([1]) == 1
    try:
        halve_array([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty nums must raise ValueError")
    try:
        halve_array([1, 0])
    except ValueError:
        pass
    else:
        raise AssertionError("zero must raise ValueError")
    assert stdlib_only()
    print("heap-42.v1 OK")


if __name__ == "__main__":
    main()
