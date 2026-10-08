"""LCS full DP table

What this IS: returns the complete DP table as an immutable tuple-of-tuples for inspection.

What this IS NOT:
* just the length -- see lcs_01.
* lazy row streaming -- see lcs_48.
"""

from __future__ import annotations

import ast
from typing import Tuple
#: Module version.
LCS_30_VERSION = "lcs-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-30.v1"


def lcs_table(a: str, b: str) -> Tuple[Tuple[int, ...], ...]:
    # Materialize the whole table so callers can inspect any cell.
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    return tuple(tuple(row) for row in dp)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "typing"}
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
    t = lcs_table("abcde", "ace")
    assert t[5][3] == 3 and len(t) == 6 and len(t[0]) == 4
    assert t[0] == (0, 0, 0, 0)
    assert lcs_table("", "abc")[0] == (0, 0, 0, 0)
    t = lcs_table("abc", "def")
    assert t[3][3] == 0
    assert isinstance(t, tuple) and isinstance(t[0], tuple)
    assert stdlib_only()
    print("30-ok OK")


if __name__ == "__main__":
    main()
