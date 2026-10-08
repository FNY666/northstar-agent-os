"""pairs_with_difference_k (two-pointer), count unique pairs with |a-b| == k in a sorted list. IS: a two-pointer scan over distinct values counting each distinct value-pair once (k==0 counts values occurring 2+ times). IS NOT: a counter of all index pairs (duplicate index pairs are deduped)."""
from __future__ import annotations

import ast

VERSION = "twop-47.v1"


def _is_number(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def pairs_with_difference_k(nums: list[int] | list[float], k: int | float) -> int:
    """Count unique pairs (a, b) in sorted nums with abs(a-b) == k."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    for v in nums:
        if not _is_number(v):
            raise ValueError("nums must contain only numbers")
    if not _is_number(k):
        raise ValueError("k must be a number")
    if k < 0:
        raise ValueError("k must be non-negative")
    if any(nums[i] > nums[i + 1] for i in range(len(nums) - 1)):
        raise ValueError("nums must be sorted in non-decreasing order")
    freq: dict[int | float, int] = {}
    for v in nums:
        freq[v] = freq.get(v, 0) + 1
    if k == 0:
        return sum(1 for c in freq.values() if c >= 2)
    distinct = list(freq.keys())  # sorted order preserved from sorted nums
    count = 0
    left = 0
    for right in range(len(distinct)):
        while distinct[right] - distinct[left] > k:
            left += 1
        if left < right and distinct[right] - distinct[left] == k:
            count += 1
    return count


def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert pairs_with_difference_k([1, 3, 4, 5, 6], 2) == 3  # (1,3),(3,5),(4,6)
    assert pairs_with_difference_k([1, 2, 3, 4, 5], 1) == 4
    assert pairs_with_difference_k([1, 1, 3, 4, 5], 0) == 1  # edge: k==0 counts 2+ occurrences
    assert pairs_with_difference_k([1, 2, 3], 0) == 0
    assert pairs_with_difference_k([1, 1, 2, 2], 1) == 1  # unique pair (1,2) only
    assert pairs_with_difference_k([], 1) == 0
    try:
        pairs_with_difference_k([3, 1, 2], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unsorted input")
    try:
        pairs_with_difference_k([1, 2, 3], -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative k")
    assert stdlib_only()
    print("pairs_with_difference_k OK")


if __name__ == "__main__":
    main()
