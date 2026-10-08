"""Smallest Range Covering K Lists: smallest interval covering at least one element from each list IS: min-heap tracking the current head of each list IS NOT: checking every candidate interval"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-13.v1"

def _req_lists(value):
    if not isinstance(value, list) or not value:
        raise ValueError("nums must be a non-empty list of lists")
    out = []
    for i, sub in enumerate(value):
        if not isinstance(sub, list) or not sub:
            raise ValueError(f"nums[{i}] must be a non-empty list")
        out.append(list(sub))
    return out


def smallest_range(nums):
    """Return ``[lo, hi]`` of the smallest covering range.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    nums = _req_lists(nums)
    heap = [(row[0], i, 0) for i, row in enumerate(nums)]
    heapq.heapify(heap)
    hi = max(row[0] for row in nums)
    best = [heap[0][0], hi]
    while True:
        lo, i, j = heapq.heappop(heap)
        if hi - lo < best[1] - best[0]:
            best = [lo, hi]
        if j + 1 == len(nums[i]):
            break
        nxt = nums[i][j + 1]
        heapq.heappush(heap, (nxt, i, j + 1))
        hi = max(hi, nxt)
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
    assert smallest_range([[4, 10, 15, 24, 26], [0, 9, 12, 20], [5, 18, 22, 30]]) == [20, 24]
    assert smallest_range([[1, 2, 3], [1, 2, 3], [1, 2, 3]]) == [1, 1]
    assert smallest_range([[10], [11]]) == [10, 11]
    try:
        smallest_range([[]])
    except ValueError:
        pass
    else:
        raise AssertionError("empty sublist must raise ValueError")
    assert stdlib_only()
    print("heap-13.v1 OK")


if __name__ == "__main__":
    main()
