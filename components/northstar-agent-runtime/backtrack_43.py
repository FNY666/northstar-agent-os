"""Backtracking: Target sum ways -- count assignments of +/- to each element of
nums so the signed sum equals target.

IS: depth-first search over the sign choices per position, with (index,
current-sum) memoization to collapse the exponential blowup.
IS NOT: subset-sum subset selection (signs are per-element, not inclusion),
nor a modulo/DP transformation proof -- just the direct counting search.
"""

from __future__ import annotations

VERSION = "backtrack_43.v1"


import ast
from typing import Dict, List, Tuple

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}


def find_target_sum_ways(nums: List[int], target: int) -> int:
    """Count the number of +/- assignments making the signed sum equal target."""
    memo: Dict[Tuple[int, int], int] = {}

    def backtrack(i: int, current: int) -> int:
        key = (i, current)
        if key in memo:
            return memo[key]
        if i == len(nums):
            result = 1 if current == target else 0
        else:
            result = (backtrack(i + 1, current + nums[i])
                      + backtrack(i + 1, current - nums[i]))
        memo[key] = result
        return result

    return backtrack(0, 0)


def stdlib_only() -> bool:
    """Return True only if every import in this file comes from the allowed stdlib set."""
    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.module.split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert find_target_sum_ways([1, 1, 1, 1, 1], 3) == 5
    assert find_target_sum_ways([1], 1) == 1
    assert find_target_sum_ways([1, 2, 3], 0) == 2
    assert find_target_sum_ways([], 0) == 1
    assert find_target_sum_ways([0, 0, 0, 0, 0, 0, 0, 0, 1], 1) == 256
    print("backtrack_43 OK")


if __name__ == "__main__":
    main()
