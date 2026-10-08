"""Min weight for target value

Minimize total weight while reaching at least a target value.

What this IS: the dual DP: minimize weight for each achievable value.

What this IS NOT:
* a value maximizer -- this minimizes weight for a value floor.
* a guarantee when the target is unreachable -- returns -1.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_13_VERSION = "ks-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-13.v1"


def min_weight_for_value(weights, values, target_value):
    # Min total weight achieving value >= target_value; -1 if impossible.
    if target_value < 0:
        raise ValueError("target_value must be >= 0")
    max_v = sum(values)
    inf = 10 ** 18
    dp = [inf] * (max_v + 1)
    dp[0] = 0
    for w, v in zip(weights, values):
        for val in range(max_v, v - 1, -1):
            if dp[val - v] + w < dp[val]:
                dp[val] = dp[val - v] + w
    best = min(dp[target_value:], default=inf)
    return -1 if best >= inf else best

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
    assert min_weight_for_value([1, 3, 4, 5], [1, 4, 5, 7], 9) == 7
    assert min_weight_for_value([1, 3, 4, 5], [1, 4, 5, 7], 100) == -1
    assert min_weight_for_value([2], [5], 0) == 0
    assert min_weight_for_value([2], [5], 5) == 2
    assert stdlib_only()
    print("13-min-weight OK")


if __name__ == "__main__":
    main()
