"""Memoized Distinct Subsequences: memoization example.

Count distinct subsequences of s equal to t: match adds the skip-branch, mismatch skips. The (i, j) cache gives O(|s|*|t|).

What this IS: a real memoized distinct-subsequence counter.
What this IS NOT: a subsequence enumerator; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_23_VERSION = "memo-distinct-subsequences.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-distinct-subsequences.v1"


class MemoError(Exception):
    """Fail-closed."""


def distinct_subseq(s: str, t: str, i: int = 0, j: int = 0, _cache: dict | None = None) -> int:
    """Memoized distinct-subsequence counter."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    if j == len(t):
        cache[key] = 1
    elif i == len(s):
        cache[key] = 0
    elif s[i] == t[j]:
        cache[key] = distinct_subseq(s, t, i + 1, j + 1, cache) + distinct_subseq(s, t, i + 1, j, cache)
    else:
        cache[key] = distinct_subseq(s, t, i + 1, j, cache)
    return cache[key]

def test_distinct_subseq_example():
    assert distinct_subseq("rabbbit", "rabbit") == 3


def test_distinct_subseq_empty_t():
    assert distinct_subseq("abc", "") == 1


def test_distinct_subseq_none():
    assert distinct_subseq("abc", "d") == 0

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
    test_distinct_subseq_example()
    test_distinct_subseq_empty_t()
    test_distinct_subseq_none()
    assert stdlib_only()
    print("memo-23 OK: distinct-subsequences")


if __name__ == "__main__":
    main()
