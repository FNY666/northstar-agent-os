"""Memoized Palindrome Min Cuts: memoization example.

Fewest cuts for palindromic partitioning: 1 + min over palindromic prefixes. A memoized palindrome helper shares the O(n^2) palindrome checks.

What this IS: a real memoized min-cut solver with a memoized palindrome helper.
What this IS NOT: a partition enumerator; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_35_VERSION = "memo-palindrome-min-cuts.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-palindrome-min-cuts.v1"


class MemoError(Exception):
    """Fail-closed."""


def _is_pal(s: str, i: int, j: int, _cache: dict) -> bool:
    key = (i, j)
    if key in _cache:
        return _cache[key]
    if i >= j:
        _cache[key] = True
    else:
        _cache[key] = s[i] == s[j] and _is_pal(s, i + 1, j - 1, _cache)
    return _cache[key]


def min_cuts(s: str, i: int = 0, _cache: dict | None = None, _pal_cache: dict | None = None) -> float:
    """Memoized minimum palindrome-partition cuts from i."""
    cache: dict = _cache if _cache is not None else {}
    pal_cache: dict = _pal_cache if _pal_cache is not None else {}
    if i in cache:
        return cache[i]
    if i >= len(s):
        cache[i] = -1
    else:
        best = float("inf")
        for j in range(i, len(s)):
            if _is_pal(s, i, j, pal_cache):
                best = min(best, 1 + min_cuts(s, j + 1, cache, pal_cache))
        cache[i] = best
    return cache[i]

def test_min_cuts_example():
    assert min_cuts("aab") == 1


def test_min_cuts_palindrome():
    assert min_cuts("aba") == 0


def test_min_cuts_empty():
    assert min_cuts("") == -1

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
    test_min_cuts_example()
    test_min_cuts_palindrome()
    test_min_cuts_empty()
    assert stdlib_only()
    print("memo-35 OK: palindrome-min-cuts")


if __name__ == "__main__":
    main()
