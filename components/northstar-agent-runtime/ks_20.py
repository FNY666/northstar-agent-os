"""Perfect squares (min count)

Fewest perfect squares summing to n.

What this IS: unbounded knapsack over square denominations, minimizing count.

What this IS NOT:
* a factorization -- this minimizes the number of squares.
* a guarantee faster than O(n sqrt n).
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_20_VERSION = "ks-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-20.v1"


def num_squares(n):
    # Min number of perfect squares summing to n.
    if n < 0:
        raise ValueError("n must be >= 0")
    inf = 10 ** 9
    dp = [inf] * (n + 1)
    dp[0] = 0
    s = 1
    while s * s <= n:
        sq = s * s
        for i in range(sq, n + 1):
            if dp[i - sq] + 1 < dp[i]:
                dp[i] = dp[i - sq] + 1
        s += 1
    return dp[n]

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
    assert num_squares(12) == 3
    assert num_squares(13) == 2
    assert num_squares(1) == 1
    assert num_squares(0) == 0
    assert stdlib_only()
    print("20-num-squares OK")


if __name__ == "__main__":
    main()
