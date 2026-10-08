"""Count subsets with given sum

Count how many subsets sum to the target.

What this IS: a subset counter: number of subsets hitting the target sum.

What this IS NOT:
* a feasibility check -- this counts, ks_05 only decides.
* an ordered counter -- use ks_19 when order matters.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_07_VERSION = "ks-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-07.v1"


def count_subsets(nums, target):
    # Number of subsets summing to target.
    if target < 0:
        return 0
    dp = [0] * (target + 1)
    dp[0] = 1
    for x in nums:
        if x < 0:
            raise ValueError("nums must be >= 0")
        for t in range(target, x - 1, -1):
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
    assert count_subsets([1, 2, 3, 3], 6) == 3
    assert count_subsets([1, 2, 3], 7) == 0
    assert count_subsets([], 0) == 1
    assert count_subsets([2, 2, 2], 4) == 3
    assert stdlib_only()
    print("07-count-subsets OK")


if __name__ == "__main__":
    main()
