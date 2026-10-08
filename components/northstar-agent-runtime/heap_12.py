"""K Pairs with Smallest Sums: k pairs (u, v) with the smallest sums from two sorted lists IS: min-heap expansion over the pair grid IS NOT: enumerating all pairs then sorting"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-12.v1"

def _req_sorted(value, name):
    if not isinstance(value, list) or not value:
        raise ValueError(f"{name} must be a non-empty list")
    for i, x in enumerate(value):
        if isinstance(x, bool) or not isinstance(x, (int, float)):
            raise ValueError(f"{name}[{i}] must be a number")
    return list(value)


def k_smallest_pairs(nums1, nums2, k):
    """Return k pairs with the smallest sums.

    Fail-closed: inputs must be non-empty numeric lists and
    ``1 <= k <= len(nums1)*len(nums2)``, else :class:`ValueError`.
    """
    nums1 = _req_sorted(nums1, "nums1")
    nums2 = _req_sorted(nums2, "nums2")
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("k must be an int")
    if not 1 <= k <= len(nums1) * len(nums2):
        raise ValueError("k out of range")
    heap = [(nums1[0] + nums2[0], 0, 0)]
    seen = {(0, 0)}
    out = []
    while heap and len(out) < k:
        _, i, j = heapq.heappop(heap)
        out.append([nums1[i], nums2[j]])
        if i + 1 < len(nums1) and (i + 1, j) not in seen:
            seen.add((i + 1, j))
            heapq.heappush(heap, (nums1[i + 1] + nums2[j], i + 1, j))
        if j + 1 < len(nums2) and (i, j + 1) not in seen:
            seen.add((i, j + 1))
            heapq.heappush(heap, (nums1[i] + nums2[j + 1], i, j + 1))
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
    assert k_smallest_pairs([1, 7, 11], [2, 4, 6], 3) == [[1, 2], [1, 4], [1, 6]]
    assert k_smallest_pairs([1, 1, 2], [1, 2, 3], 2) == [[1, 1], [1, 1]]
    got = k_smallest_pairs([1, 2], [3], 2)
    assert got == [[1, 3], [2, 3]], got
    try:
        k_smallest_pairs([], [1], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("empty nums1 must raise ValueError")
    assert stdlib_only()
    print("heap-12.v1 OK")


if __name__ == "__main__":
    main()
