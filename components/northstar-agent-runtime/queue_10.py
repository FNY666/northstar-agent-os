"""first_negative_in_window: first negative number in every sliding window of size k (0 if none). IS: a per-window first-negative scan; k outside [1, n] raises ValueError. IS NOT: an O(n*k) nested-loop implementation."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-10.v1"

def first_negative_in_window(nums: List[float], k: int) -> List[float]:
    """Return the first negative in each window of size ``k``, else ``0``."""
    if not isinstance(nums, list) or not nums:
        raise ValueError("nums must be a non-empty list")
    for x in nums:
        if isinstance(x, bool) or not isinstance(x, (int, float)):
            raise ValueError("nums must contain only real numbers")
    if isinstance(k, bool) or not isinstance(k, int) or k < 1 or k > len(nums):
        raise ValueError("k must satisfy 1 <= k <= len(nums)")
    dq: deque = deque()  # indices of negatives in the current window
    out: List[float] = []
    for i, x in enumerate(nums):
        if x < 0:
            dq.append(i)
        while dq and dq[0] <= i - k:
            dq.popleft()
        if i >= k - 1:
            out.append(nums[dq[0]] if dq else 0)
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
    assert first_negative_in_window([12, -1, -7, 8, -15, 30, 16, 28], 3) == [-1, -1, -7, -15, -15, 0]
    assert first_negative_in_window([1, 2, 3], 2) == [0, 0]
    assert first_negative_in_window([-5], 1) == [-5]
    assert first_negative_in_window([3, -2, -1], 3) == [-2]
    for bad_k in (0, 5, "3"):
        try:
            first_negative_in_window([1, 2, 3, 4], bad_k)
        except ValueError:
            pass
        else:
            raise AssertionError(f"k={bad_k!r} must raise ValueError")
    assert stdlib_only()
    print("queue-10 OK: first negative per window")


if __name__ == "__main__":
    main()
