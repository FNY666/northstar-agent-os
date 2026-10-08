"""Minimum subset sum difference

Split numbers into two groups minimizing the absolute sum difference.

What this IS: the min-difference partition: closest achievable split.

What this IS NOT:
* a value maximizer -- this minimizes imbalance.
* a stone simulator -- use ks_10 for the last-stone framing.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_09_VERSION = "ks-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-09.v1"


def min_subset_diff(nums):
    # Minimize |sum(A) - sum(B)| over partition.
    total = sum(nums)
    reachable = {0}
    for x in nums:
        reachable |= {r + x for r in reachable}
    return min(abs(total - 2 * d) for d in reachable)

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
    assert min_subset_diff([1, 6, 11, 5]) == 1
    assert min_subset_diff([1, 2, 3]) == 0
    assert min_subset_diff([]) == 0
    assert min_subset_diff([5]) == 5
    assert stdlib_only()
    print("09-min-diff OK")


if __name__ == "__main__":
    main()
