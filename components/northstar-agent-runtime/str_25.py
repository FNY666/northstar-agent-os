"""Damerau-Levenshtein distance: edit distance with transpositions.

Optimal string alignment: adjacent transposition costs 1 alongside insert/delete/substitute.

What this IS: a real OSA implementation.
What this IS NOT: true Damerau-Levenshtein with multiple edits on overlapping substrings.
"""

from __future__ import annotations

import ast

#: Module version.
STR_25_VERSION = "str-damerau.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-damerau-levenshtein.v1"


class StrError(Exception):
    """Fail-closed."""


def damerau_levenshtein(a: str, b: str) -> int:
    """Edit distance where adjacent transposition costs 1."""
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                dp[i][j] = min(dp[i][j], dp[i - 2][j - 2] + 1)
    return dp[m][n]


def test_dl_transposition():
    assert damerau_levenshtein("abcd", "acbd") == 1


def test_dl_classic():
    assert damerau_levenshtein("kitten", "sitting") == 3


def test_dl_empty():
    assert damerau_levenshtein("", "abc") == 3


def test_dl_same():
    assert damerau_levenshtein("abc", "abc") == 0


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_dl_transposition()
    test_dl_classic()
    test_dl_empty()
    test_dl_same()
    assert stdlib_only()
    print("str-25 OK: damerau")


if __name__ == "__main__":
    main()
