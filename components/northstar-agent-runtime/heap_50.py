"""Find Score of an Array After Marking All Elements: score from repeatedly marking the smallest unmarked element IS: min-heap of (value, index) skipping marked entries IS NOT: sorting then scanning"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-50.v1"

def _req_nums(value):
    if not isinstance(value, list) or not value:
        raise ValueError("nums must be a non-empty list")
    for i, x in enumerate(value):
        if isinstance(x, bool) or not isinstance(x, (int, float)):
            raise ValueError(f"nums[{i}] must be a number")
    return list(value)


def find_score(nums):
    """Return the score after marking all elements.

    Fail-closed: ``nums`` must be a non-empty list of numbers,
    else :class:`ValueError`.
    """
    nums = _req_nums(nums)
    n = len(nums)
    heap = [(v, i) for i, v in enumerate(nums)]
    heapq.heapify(heap)
    marked = [False] * n
    score = 0
    while heap:
        v, i = heapq.heappop(heap)
        if marked[i]:
            continue
        score += v
        marked[i] = True
        if i > 0:
            marked[i - 1] = True
        if i + 1 < n:
            marked[i + 1] = True
    return score

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
    assert find_score([2, 1, 3, 4, 5, 2]) == 7
    assert find_score([2, 3, 5, 1, 3, 2]) == 5
    assert find_score([9]) == 9
    try:
        find_score([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty nums must raise ValueError")
    assert stdlib_only()
    print("heap-50.v1 OK")


if __name__ == "__main__":
    main()
