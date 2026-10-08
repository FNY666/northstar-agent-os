"""Meet-in-the-middle knapsack

Exact 0/1 knapsack for n <= 40 via meet-in-the-middle.

What this IS: meet-in-the-middle 0/1 knapsack, fast for small n and huge capacity.

What this IS NOT:
* a DP over capacity -- this splits the item set instead.
* a solver for n > 40 -- it refuses instead.
"""

from __future__ import annotations

import ast
import bisect

from typing import Dict, List, Set, Tuple

#: Module version.
KS_33_VERSION = "ks-33.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-33.v1"


def knapsack_meet_middle(weights, values, capacity):
    # Meet-in-the-middle; requires n <= 40.
    if capacity < 0:
        raise ValueError("capacity must be >= 0")
    n = len(weights)
    if n > 40:
        raise ValueError("too many items for meet-in-the-middle")

    def gen(idxs):
        subs = [(0, 0)]
        for i in idxs:
            subs += [(w + weights[i], v + values[i]) for w, v in subs]
        return [(w, v) for w, v in subs if w <= capacity]

    right = sorted(gen(range(n // 2, n)))
    pruned = []
    best = -1
    for w, v in right:
        if v > best:
            pruned.append((w, v))
            best = v
    ws = [w for w, _ in pruned]
    ans = 0
    for w, v in gen(range(n // 2)):
        j = bisect.bisect_right(ws, capacity - w) - 1
        if j >= 0 and v + pruned[j][1] > ans:
            ans = v + pruned[j][1]
    return ans

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "bisect"}
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
    assert knapsack_meet_middle([1, 3, 4, 5], [1, 4, 5, 7], 7) == 9
    assert knapsack_meet_middle([], [], 5) == 0
    assert knapsack_meet_middle([10], [100], 5) == 0
    assert knapsack_meet_middle([2, 2], [3, 5], 3) == 5
    assert stdlib_only()
    print("33-meet-middle OK")


if __name__ == "__main__":
    main()
