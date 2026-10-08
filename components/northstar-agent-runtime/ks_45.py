"""Online knapsack (mock)

Items arrive one by one; take/skip decisions are immediate.

What this IS: a mock online knapsack: density-vs-average threshold rule.

What this IS NOT:
* an offline solver -- decisions here are irrevocable.
* a competitive-ratio guarantee.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_45_VERSION = "ks-45.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-45.v1"


def knapsack_online(weights, values, capacity):
    # Mock online: take item if its density >= running average density.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    total = 0
    rem = capacity
    seen = []
    for w, v in zip(weights, values):
        r = (v / w) if w > 0 else 0.0
        seen.append(r)
        avg = sum(seen) / len(seen)
        if r >= avg and w <= rem:
            total += v
            rem -= w
    return total

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
    assert knapsack_online([2, 2], [4, 6], 5) == 10
    assert knapsack_online([], [], 5) == 0
    assert knapsack_online([6], [10], 5) == 0
    assert knapsack_online([2, 3], [6, 6], 5) == 6
    assert stdlib_only()
    print("45-online OK")


if __name__ == "__main__":
    main()
