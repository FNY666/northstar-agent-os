"""Memoized Longest Common Subsequence: memoization example.

LCS over index pairs (i, j): match extends by 1, mismatch takes the max of skipping either side. The (i, j) cache gives O(|a|*|b|).

What this IS: a real memoized LCS length, fail-closed on nothing but honest about non-string input.
What this IS NOT: a diff or alignment builder; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_06_VERSION = "memo-lcs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-lcs.v1"


class MemoError(Exception):
    """Fail-closed."""


def lcs(a: str, b: str, i: int = 0, j: int = 0, _cache: dict | None = None) -> int:
    """Memoized LCS length."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    if i >= len(a) or j >= len(b):
        cache[key] = 0
    elif a[i] == b[j]:
        cache[key] = 1 + lcs(a, b, i + 1, j + 1, cache)
    else:
        cache[key] = max(lcs(a, b, i + 1, j, cache), lcs(a, b, i, j + 1, cache))
    return cache[key]

def test_lcs_example():
    assert lcs("abcde", "ace") == 3


def test_lcs_empty():
    assert lcs("", "abc") == 0


def test_lcs_identical():
    assert lcs("northstar", "northstar") == 9

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
    test_lcs_example()
    test_lcs_empty()
    test_lcs_identical()
    assert stdlib_only()
    print("memo-06 OK: lcs")


if __name__ == "__main__":
    main()
