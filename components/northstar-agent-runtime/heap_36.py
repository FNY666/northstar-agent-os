"""Sliding Window Median: median of each sliding window of size k IS: two heaps with lazy deletion IS NOT: sorting every window"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-36.v1"

class _DualHeap:
    def __init__(self, k) -> None:
        self._small = []
        self._large = []
        self._delayed = {}
        self._k = k
        self._small_size = 0
        self._large_size = 0

    def _prune(self, heap):
        while heap:
            num = -heap[0] if heap is self._small else heap[0]
            if self._delayed.get(num, 0):
                self._delayed[num] -= 1
                if self._delayed[num] == 0:
                    del self._delayed[num]
                heapq.heappop(heap)
            else:
                break

    def _balance(self):
        if self._small_size > self._large_size + 1:
            heapq.heappush(self._large, -heapq.heappop(self._small))
            self._small_size -= 1
            self._large_size += 1
            self._prune(self._small)
        elif self._small_size < self._large_size:
            heapq.heappush(self._small, -heapq.heappop(self._large))
            self._small_size += 1
            self._large_size -= 1
            self._prune(self._large)

    def insert(self, num):
        if not self._small or num <= -self._small[0]:
            heapq.heappush(self._small, -num)
            self._small_size += 1
        else:
            heapq.heappush(self._large, num)
            self._large_size += 1
        self._balance()

    def erase(self, num):
        self._delayed[num] = self._delayed.get(num, 0) + 1
        if self._small and num <= -self._small[0]:
            self._small_size -= 1
            if num == -self._small[0]:
                self._prune(self._small)
        else:
            self._large_size -= 1
            if self._large and num == self._large[0]:
                self._prune(self._large)
        self._balance()

    def median(self):
        if self._k % 2 == 1:
            return float(-self._small[0])
        return (-self._small[0] + self._large[0]) / 2.0


def _req_inputs(nums, k):
    if not isinstance(nums, list) or not nums:
        raise ValueError("nums must be a non-empty list")
    for i, x in enumerate(nums):
        if isinstance(x, bool) or not isinstance(x, (int, float)):
            raise ValueError(f"nums[{i}] must be a number")
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= len(nums):
        raise ValueError("k must satisfy 1 <= k <= len(nums)")
    return list(nums), k


def median_sliding_window(nums, k):
    """Return the median of each window of size ``k``.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    nums, k = _req_inputs(nums, k)
    dh = _DualHeap(k)
    for x in nums[:k]:
        dh.insert(x)
    out = [dh.median()]
    for i in range(k, len(nums)):
        dh.insert(nums[i])
        dh.erase(nums[i - k])
        out.append(dh.median())
    return out

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
    assert median_sliding_window([1, 3, -1, -3, 5, 3, 6, 7], 3) == [1.0, -1.0, -1.0, 3.0, 5.0, 6.0]
    assert median_sliding_window([1, 2, 3, 4, 2, 3, 1, 4, 2], 3) == [2.0, 3.0, 3.0, 3.0, 2.0, 3.0, 2.0]
    assert median_sliding_window([5], 1) == [5.0]
    assert median_sliding_window([1, 4, 2, 3], 4) == [2.5]
    try:
        median_sliding_window([1, 2], 3)
    except ValueError:
        pass
    else:
        raise AssertionError("k > len must raise ValueError")
    assert stdlib_only()
    print("heap-36.v1 OK")


if __name__ == "__main__":
    main()
