"""Longest common increasing subsequence

What this IS: longest subsequence common to both and strictly increasing: O(n*m).

What this IS NOT:
* plain LCS -- see lcs_01 (order only, no monotonicity).
* LIS of one sequence -- a different single-sequence problem.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_29_VERSION = "lcs-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-29.v1"


def lcis(a, b) -> int:
    # For each x in a, extend the best increasing run ending below x.
    n = len(b)
    dp = [0] * n
    for x in a:
        best = 0
        for j in range(n):
            if x == b[j]:
                if best + 1 > dp[j]:
                    dp[j] = best + 1
            elif x > b[j]:
                if dp[j] > best:
                    best = dp[j]
    return max(dp) if dp else 0

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
    assert lcis([1, 4, 2, 3], [1, 2, 3, 4]) == 3
    assert lcis([3, 2, 1], [1, 2, 3]) == 1
    assert lcis([], []) == 0
    assert lcis([1, 2, 3], [1, 2, 3]) == 3
    assert lcis([1, 3, 2], [1, 2, 3]) == 2
    assert stdlib_only()
    print("29-ok OK")


if __name__ == "__main__":
    main()
