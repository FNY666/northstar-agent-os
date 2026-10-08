"""Optimal string alignment distance

Restricted Damerau-Levenshtein: each substring edited at most once.

What this IS: OSA: adjacent transposition allowed once per substring pair.

What this IS NOT:
* true Damerau-Levenshtein -- ed_02 allows multiple edits per substring.
* plain Levenshtein -- transpositions cost 1 here.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_21_VERSION = "ed-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-21.v1"


def osa_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (restricted Damerau-Levenshtein)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                           dp[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                dp[i][j] = min(dp[i][j], dp[i - 2][j - 2] + 1)
    return dp[m][n]

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
    assert osa_distance("ca", "abc") == 3
    assert osa_distance("abcd", "acbd") == 1
    assert osa_distance("abc", "abc") == 0
    assert osa_distance("", "ab") == 2
    try:
        osa_distance("a", 8)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("21-osa OK")


if __name__ == "__main__":
    main()
