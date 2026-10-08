"""Total Cost to Hire K Workers: minimum total cost hiring k workers from either end IS: two min-heaps over the left and right candidate windows IS NOT: trying every hiring order"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-40.v1"

def _req_inputs(costs, k, candidates):
    if not isinstance(costs, list) or not costs:
        raise ValueError("costs must be a non-empty list")
    for i, x in enumerate(costs):
        if isinstance(x, bool) or not isinstance(x, (int, float)) or x < 0:
            raise ValueError(f"costs[{i}] must be non-negative")
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= len(costs):
        raise ValueError("k must satisfy 1 <= k <= len(costs)")
    if isinstance(candidates, bool) or not isinstance(candidates, int) or candidates < 1:
        raise ValueError("candidates must be a positive int")
    return list(costs), k, candidates


def total_cost(costs, k, candidates):
    """Return the minimum total hiring cost.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    costs, k, candidates = _req_inputs(costs, k, candidates)
    n = len(costs)
    left = []
    right = []
    i, j = 0, n - 1
    total = 0
    for _ in range(k):
        while len(left) < candidates and i <= j:
            heapq.heappush(left, costs[i])
            i += 1
        while len(right) < candidates and i <= j:
            heapq.heappush(right, costs[j])
            j -= 1
        if right and (not left or right[0] < left[0]):
            total += heapq.heappop(right)
        else:
            total += heapq.heappop(left)
    return total

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
    assert total_cost([17, 12, 10, 2, 7, 2, 11, 20, 8], 3, 4) == 11
    assert total_cost([1, 2, 4, 1], 3, 3) == 4
    assert total_cost([5], 1, 1) == 5
    try:
        total_cost([], 1, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("empty costs must raise ValueError")
    try:
        total_cost([1, 2], 3, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("k > len must raise ValueError")
    assert stdlib_only()
    print("heap-40.v1 OK")


if __name__ == "__main__":
    main()
