"""sliding_window_maximum: maximum of every sliding window of size k in O(n) with a monotone deque. IS: a linear-time sliding-window maximum; k outside [1, n] raises ValueError. IS NOT: a heap-based or O(n*k) brute-force variant."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-09.v1"

def _req_nums(nums: object) -> List[float]:
    if not isinstance(nums, list) or not nums:
        raise ValueError("nums must be a non-empty list")
    for x in nums:
        if isinstance(x, bool) or not isinstance(x, (int, float)):
            raise ValueError("nums must contain only real numbers")
    return list(nums)


def sliding_window_maximum(nums: List[float], k: int) -> List[float]:
    """Return the max of each contiguous window of size ``k``."""
    nums = _req_nums(nums)
    if isinstance(k, bool) or not isinstance(k, int) or k < 1 or k > len(nums):
        raise ValueError("k must satisfy 1 <= k <= len(nums)")
    dq: deque = deque()  # indices with decreasing values
    out: List[float] = []
    for i, x in enumerate(nums):
        while dq and dq[0] <= i - k:
            dq.popleft()
        while dq and nums[dq[-1]] <= x:
            dq.pop()
        dq.append(i)
        if i >= k - 1:
            out.append(nums[dq[0]])
    return out


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
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
    assert sliding_window_maximum([1, 3, -1, -3, 5, 3, 6, 7], 3) == [3, 3, 5, 5, 6, 7]
    assert sliding_window_maximum([4, 2, 9], 1) == [4, 2, 9]
    assert sliding_window_maximum([4, 2, 9], 3) == [9]
    assert sliding_window_maximum([5, 5, 5, 5], 2) == [5, 5, 5]
    for bad_k in (0, 4, "2", 2.0, True):
        try:
            sliding_window_maximum([1, 2, 3], bad_k)
        except ValueError:
            pass
        else:
            raise AssertionError(f"k={bad_k!r} must raise ValueError")
    try:
        sliding_window_maximum([], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("empty nums must raise ValueError")
    assert stdlib_only()
    print("queue-09 OK: sliding window maximum")


if __name__ == "__main__":
    main()
