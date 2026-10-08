"""Interleaving (shuffle) check: 1-D DP shuffle test.

c is an interleaving of a and b iff a DP over the grid reaches (m,n).

What this IS: a real O(m*n) time / O(n) space DP.
What this IS NOT: counting interleavings; that's combinatorics.
"""

from __future__ import annotations

import ast

#: Module version.
STR_17_VERSION = "str-interleave.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-interleave-check.v1"


class StrError(Exception):
    """Fail-closed."""


def is_interleave(a: str, b: str, c: str) -> bool:
    """True iff c is a shuffle (interleaving) of a and b preserving order."""
    if len(a) + len(b) != len(c):
        return False
    m, n = len(a), len(b)
    dp = [False] * (n + 1)
    dp[0] = True
    for j in range(1, n + 1):
        dp[j] = dp[j - 1] and b[j - 1] == c[j - 1]
    for i in range(1, m + 1):
        dp[0] = dp[0] and a[i - 1] == c[i - 1]
        for j in range(1, n + 1):
            dp[j] = (dp[j] and a[i - 1] == c[i + j - 1]) or (dp[j - 1] and b[j - 1] == c[i + j - 1])
    return dp[n]


def test_interleave_true():
    assert is_interleave("aabcc", "dbbca", "aadbbcbcac") is True


def test_interleave_false():
    assert is_interleave("aabcc", "dbbca", "aadbbbaccc") is False


def test_interleave_empty():
    assert is_interleave("", "", "") is True


def test_interleave_len():
    assert is_interleave("a", "b", "abc") is False


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
    test_interleave_true()
    test_interleave_false()
    test_interleave_empty()
    test_interleave_len()
    assert stdlib_only()
    print("str-17 OK: interleave")


if __name__ == "__main__":
    main()
