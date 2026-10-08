"""Memoized Longest Palindromic Subsequence: memoization example.

LPS over (i, j): matching ends add 2, else take the max of shrinking either side. The (i, j) cache gives O(n^2).

What this IS: a real memoized LPS length.
What this IS NOT: a palindrome reconstructor; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_19_VERSION = "memo-longest-palindromic-subseq.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-longest-palindromic-subseq.v1"


class MemoError(Exception):
    """Fail-closed."""


def lps(s: str, i: int = 0, j: int | None = None, _cache: dict | None = None) -> int:
    """Memoized longest palindromic subsequence length."""
    if j is None:
        j = len(s) - 1
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    if i > j:
        cache[key] = 0
    elif i == j:
        cache[key] = 1
    elif s[i] == s[j]:
        cache[key] = 2 + lps(s, i + 1, j - 1, cache)
    else:
        cache[key] = max(lps(s, i + 1, j, cache), lps(s, i, j - 1, cache))
    return cache[key]

def test_lps_example():
    assert lps("bbbab") == 4


def test_lps_single():
    assert lps("a") == 1


def test_lps_empty():
    assert lps("") == 0

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
    test_lps_example()
    test_lps_single()
    test_lps_empty()
    assert stdlib_only()
    print("memo-19 OK: longest-palindromic-subseq")


if __name__ == "__main__":
    main()
