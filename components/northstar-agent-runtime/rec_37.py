"""Longest common subsequence: match-or-skip, memoised

Classic DP recursion over both string indices; O(m*n) with memo.

What this IS: a real memoised recursive LCS length.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_37_VERSION = "rec-lcs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-lcs.v1"


class RecError(Exception):
    """Fail-closed."""


def lcs(a: str, b: str) -> int:
    """Length of the longest common subsequence."""
    memo = {}

    def rec(i, j) -> int:
        if i == len(a) or j == len(b):
            return 0
        if (i, j) in memo:
            return memo[(i, j)]
        if a[i] == b[j]:
            r = 1 + rec(i + 1, j + 1)
        else:
            r = max(rec(i + 1, j), rec(i, j + 1))
        memo[(i, j)] = r
        return r

    return rec(0, 0)

def test_lcs_basic():
    assert lcs("abcde", "ace") == 3


def test_lcs_empty():
    assert lcs("", "abc") == 0


def test_lcs_identical():
    assert lcs("abc", "abc") == 3


def test_lcs_none():
    assert lcs("abc", "def") == 0

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_lcs_basic()
    test_lcs_empty()
    test_lcs_identical()
    test_lcs_none()
    assert stdlib_only()
    print("rec-lcs OK")


if __name__ == "__main__":
    main()
