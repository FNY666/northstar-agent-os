"""Levenshtein distance (classic)

The textbook edit distance: unit-cost insert, delete, substitute.

What this IS: the classic Wagner-Fischer dynamic program, O(m*n) time and space.

What this IS NOT:
* a Damerau-Levenshtein variant -- a transposition costs 2 here.
* a thresholded check -- see ed_12 for the bounded version.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_01_VERSION = "ed-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-01.v1"


def levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein distance (full-matrix Wagner-Fischer)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        ai = a[i - 1]
        row = dp[i]
        prev = dp[i - 1]
        for j in range(1, n + 1):
            cost = 0 if ai == b[j - 1] else 1
            row[j] = min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + cost)
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
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("flaw", "lawn") == 2
    assert levenshtein("saturday", "sunday") == 3
    try:
        levenshtein(123, "abc")
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("01-levenshtein OK")


if __name__ == "__main__":
    main()
