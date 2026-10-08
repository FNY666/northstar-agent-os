"""Combination sum IV (ordered)

Count ordered combinations of numbers summing to the target.

What this IS: unbounded knapsack where order of picks matters.

What this IS NOT:
* a combination counter -- order is irrelevant in ks_18.
* a subset solver -- reuse of numbers is allowed here.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_19_VERSION = "ks-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-19.v1"


def combination_sum4(nums, target):
    # Count ordered combinations summing to target.
    if target < 0:
        return 0
    dp = [0] * (target + 1)
    dp[0] = 1
    for t in range(1, target + 1):
        for x in nums:
            if 0 < x <= t:
                dp[t] += dp[t - x]
    return dp[target]

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
    assert combination_sum4([1, 2, 3], 4) == 7
    assert combination_sum4([9], 3) == 0
    assert combination_sum4([1], 0) == 1
    assert combination_sum4([1, 2], 3) == 3
    assert stdlib_only()
    print("19-comb-sum4 OK")


if __name__ == "__main__":
    main()
