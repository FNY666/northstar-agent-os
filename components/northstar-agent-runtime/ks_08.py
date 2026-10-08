"""Target sum (+/- assignment)

Assign + or - to each number to reach a target; count assignments.

What this IS: the +/- sign assignment problem reduced to subset sum.

What this IS NOT:
* a subset finder -- this counts sign assignments.
* valid for negative targets without the abs() guard.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_08_VERSION = "ks-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-08.v1"


def find_target_sum_ways(nums, target):
    # Assign +/- to reach target; count assignments.
    total = sum(nums)
    if abs(target) > total or (total + target) % 2:
        return 0
    need = (total + target) // 2
    dp = [0] * (need + 1)
    dp[0] = 1
    for x in nums:
        for t in range(need, x - 1, -1):
            dp[t] += dp[t - x]
    return dp[need]

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    assert find_target_sum_ways([1, 1, 1, 1, 1], 3) == 5
    assert find_target_sum_ways([1], 2) == 0
    assert find_target_sum_ways([1, 2], 3) == 1
    assert find_target_sum_ways([], 0) == 1
    assert stdlib_only()
    print("08-target-sum OK")


if __name__ == "__main__":
    main()
