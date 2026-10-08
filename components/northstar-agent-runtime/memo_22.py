"""Memoized Longest Common Substring: memoization example.

Longest *contiguous* common block: a helper computes the common prefix length at (i, j) with a mismatch resetting to 0, and the wrapper takes the max over all pairs.

What this IS: a real memoized contiguous-substring solver via a prefix-length helper.
What this IS NOT: a subsequence solver (see memo-06); the host picks the variant.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_22_VERSION = "memo-longest-common-substring.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-longest-common-substring.v1"


class MemoError(Exception):
    """Fail-closed."""


def _prefix_len(a: str, b: str, i: int, j: int, _cache: dict) -> int:
    key = (i, j)
    if key in _cache:
        return _cache[key]
    if i >= len(a) or j >= len(b) or a[i] != b[j]:
        _cache[key] = 0
    else:
        _cache[key] = 1 + _prefix_len(a, b, i + 1, j + 1, _cache)
    return _cache[key]


def longest_common_substring(a: str, b: str) -> int:
    """Longest contiguous common substring length."""
    cache: dict = {}
    return max((_prefix_len(a, b, i, j, cache) for i in range(len(a)) for j in range(len(b))), default=0)

def test_longest_common_substring_example():
    assert longest_common_substring("abcde", "abfce") == 2


def test_longest_common_substring_none():
    assert longest_common_substring("abc", "xyz") == 0


def test_longest_common_substring_full():
    assert longest_common_substring("same", "same") == 4

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
    test_longest_common_substring_example()
    test_longest_common_substring_none()
    test_longest_common_substring_full()
    assert stdlib_only()
    print("memo-22 OK: longest-common-substring")


if __name__ == "__main__":
    main()
