"""Word break: DP segmentation test.

dp[i] = s[:i] segmentable; O(n^2) naive, O(n * maxlen) with trie (not here).

What this IS: a real DP implementation.
What this IS NOT: returning the segmentation itself.
"""

from __future__ import annotations

import ast

#: Module version.
STR_34_VERSION = "str-word-break.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-word-break.v1"


class StrError(Exception):
    """Fail-closed."""


def word_break(s: str, words) -> bool:
    """True iff s segments into words from the dictionary."""
    ws = set(words)
    dp = [False] * (len(s) + 1)
    dp[0] = True
    for i in range(1, len(s) + 1):
        dp[i] = any(dp[j] and s[j:i] in ws for j in range(i))
    return dp[len(s)]


def test_wb_true():
    assert word_break("leetcode", ["leet", "code"]) is True


def test_wb_reuse():
    assert word_break("applepenapple", ["apple", "pen"]) is True


def test_wb_false():
    assert word_break("catsandog", ["cats", "dog", "sand", "and", "cat"]) is False


def test_wb_empty():
    assert word_break("", ["a"]) is True


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
    test_wb_true()
    test_wb_reuse()
    test_wb_false()
    test_wb_empty()
    assert stdlib_only()
    print("str-34 OK: word-break")


if __name__ == "__main__":
    main()
