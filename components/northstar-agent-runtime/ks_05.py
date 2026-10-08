"""Subset sum

Decide whether some subset of numbers sums to a target.

What this IS: the subset-sum decision problem, the core of many knapsack variants.

What this IS NOT:
* a value maximizer -- this is pure feasibility.
* a counter -- use ks_07 to count subsets.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_05_VERSION = "ks-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-05.v1"


def subset_sum(nums, target):
    # True iff some subset sums to target.
    if target < 0:
        return False
    reachable = {0}
    for x in nums:
        if x < 0:
            raise ValueError("nums must be >= 0")
        reachable |= {r + x for r in reachable if r + x <= target}
    return target in reachable

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
    assert subset_sum([3, 34, 4, 12, 5, 2], 9) is True
    assert subset_sum([1, 2, 3], 7) is False
    assert subset_sum([], 0) is True
    assert subset_sum([1], 1) is True
    assert stdlib_only()
    print("05-subset-sum OK")


if __name__ == "__main__":
    main()
