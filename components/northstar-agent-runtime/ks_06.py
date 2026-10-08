"""Partition equal subset sum

Decide whether numbers split into two subsets of equal sum.

What this IS: the partition problem reduced to subset sum on half the total.

What this IS NOT:
* a value maximizer -- this is pure feasibility.
* a general target-sum solver -- the target is fixed at half.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_06_VERSION = "ks-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-06.v1"


def can_partition(nums):
    # True iff nums split into two equal-sum subsets.
    total = sum(nums)
    if total % 2:
        return False
    target = total // 2
    reachable = {0}
    for x in nums:
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
    assert can_partition([1, 5, 11, 5]) is True
    assert can_partition([1, 2, 3, 5]) is False
    assert can_partition([]) is True
    assert can_partition([1]) is False
    assert stdlib_only()
    print("06-partition OK")


if __name__ == "__main__":
    main()
