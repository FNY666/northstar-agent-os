"""Longest common substring: contiguous DP.

1-D DP tracking runs of equal suffixes; returns one longest common substring.

What this IS: a real O(m*n) time / O(n) space implementation.
What this IS NOT: all longest substrings.
"""

from __future__ import annotations

import ast

#: Module version.
STR_23_VERSION = "str-lcsubstr.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-longest-common-substring.v1"


class StrError(Exception):
    """Fail-closed."""


def longest_common_substring(a: str, b: str) -> str:
    """Return one longest common (contiguous) substring."""
    m, n = len(a), len(b)
    dp = [0] * (n + 1)
    best = 0
    end = 0
    for i in range(1, m + 1):
        new = [0] * (n + 1)
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                new[j] = dp[j - 1] + 1
                if new[j] > best:
                    best = new[j]
                    end = i
        dp = new
    return a[end - best:end]


def test_lcsubstr_basic():
    assert longest_common_substring("abcdef", "zcdemf") == "cde"


def test_lcsubstr_none():
    assert longest_common_substring("abc", "def") == ""


def test_lcsubstr_full():
    assert longest_common_substring("abc", "abc") == "abc"


def test_lcsubstr_empty():
    assert longest_common_substring("", "abc") == ""


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
    test_lcsubstr_basic()
    test_lcsubstr_none()
    test_lcsubstr_full()
    test_lcsubstr_empty()
    assert stdlib_only()
    print("str-23 OK: lcsubstr")


if __name__ == "__main__":
    main()
