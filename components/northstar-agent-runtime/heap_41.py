"""Maximum Subsequence Score: maximum score of a subsequence of length k IS: sort by nums2, min-heap of nums1 IS NOT: enumerating all subsequences"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-41.v1"

def _req_inputs(nums1, nums2, k):
    if not isinstance(nums1, list) or not isinstance(nums2, list):
        raise ValueError("nums1 and nums2 must be lists")
    if not nums1 or len(nums1) != len(nums2):
        raise ValueError("nums1 and nums2 must be non-empty and equal length")
    for name, v in (("nums1", nums1), ("nums2", nums2)):
        for i, x in enumerate(v):
            if isinstance(x, bool) or not isinstance(x, (int, float)) or x < 0:
                raise ValueError(f"{name}[{i}] must be non-negative")
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= len(nums1):
        raise ValueError("k must satisfy 1 <= k <= len(nums1)")
    return list(nums1), list(nums2), k


def max_score(nums1, nums2, k):
    """Return the maximum subsequence score.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    nums1, nums2, k = _req_inputs(nums1, nums2, k)
    order = sorted(range(len(nums1)), key=lambda i: nums2[i], reverse=True)
    heap = []
    total = 0
    best = 0
    for i in order:
        heapq.heappush(heap, nums1[i])
        total += nums1[i]
        if len(heap) > k:
            total -= heapq.heappop(heap)
        if len(heap) == k:
            best = max(best, total * nums2[i])
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
    assert max_score([1, 3, 3, 2], [2, 1, 3, 4], 3) == 12
    assert max_score([4, 2, 3, 1, 1], [7, 5, 10, 9, 6], 1) == 30
    assert max_score([2, 1, 14, 12], [11, 7, 13, 6], 3) == 168
    try:
        max_score([1], [1, 2], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("length mismatch must raise ValueError")
    assert stdlib_only()
    print("heap-41.v1 OK")


if __name__ == "__main__":
    main()
