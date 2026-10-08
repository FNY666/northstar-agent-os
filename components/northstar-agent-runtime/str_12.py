"""Longest palindromic subsequence: O(n) space DP.

1-D DP over intervals from the end; dp[j] tracks best for s[i..j].

What this IS: a real O(n)-space implementation.
What this IS NOT: reconstruction of the subsequence string.
"""

from __future__ import annotations

import ast

#: Module version.
STR_12_VERSION = "str-lps.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-longest-palindromic-subseq.v1"


class StrError(Exception):
    """Fail-closed."""


def longest_palindromic_subseq(s: str) -> int:
    """Length of the longest palindromic subsequence."""
    n = len(s)
    if n == 0:
        return 0
    dp = [0] * n
    for i in range(n - 1, -1, -1):
        dp[i] = 1
        prev = 0
        for j in range(i + 1, n):
            tmp = dp[j]
            if s[i] == s[j]:
                dp[j] = prev + 2
            else:
                dp[j] = dp[j] if dp[j] >= dp[j - 1] else dp[j - 1]
            prev = tmp
    return dp[n - 1]


def test_lps_classic():
    assert longest_palindromic_subseq("bbbab") == 4


def test_lps_even():
    assert longest_palindromic_subseq("cbbd") == 2


def test_lps_empty():
    assert longest_palindromic_subseq("") == 0


def test_lps_single():
    assert longest_palindromic_subseq("a") == 1


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
    test_lps_classic()
    test_lps_even()
    test_lps_empty()
    test_lps_single()
    assert stdlib_only()
    print("str-12 OK: lps")


if __name__ == "__main__":
    main()
