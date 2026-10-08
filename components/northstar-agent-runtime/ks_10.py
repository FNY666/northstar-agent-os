"""Last stone weight II

Smash stones pairwise; minimize the last remaining weight.

What this IS: last-stone-weight-II reduced to min subset difference.

What this IS NOT:
* a simulator of the smashing process -- DP finds the optimum directly.
* valid when stone weights can be negative.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_10_VERSION = "ks-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-10.v1"


def last_stone_weight_ii(stones):
    # Min possible last stone weight == min subset difference.
    total = sum(stones)
    reachable = {0}
    for x in stones:
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
    assert last_stone_weight_ii([2, 7, 4, 1, 8, 1]) == 1
    assert last_stone_weight_ii([31, 26, 33, 21, 40]) == 5
    assert last_stone_weight_ii([]) == 0
    assert last_stone_weight_ii([7]) == 7
    assert stdlib_only()
    print("10-last-stone OK")


if __name__ == "__main__":
    main()
