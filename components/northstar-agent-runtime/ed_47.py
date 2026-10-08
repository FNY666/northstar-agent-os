"""Recursive Levenshtein with memoization

Top-down recursive edit distance with an explicit memo dict.

What this IS: the recursive definition plus memoization; same value as ed_01.

What this IS NOT:
* iterative DP -- this recurses on (i, j) suffixes.
* functools.lru_cache -- the memo table is a plain dict.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_47_VERSION = "ed-47.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-47.v1"


def levenshtein_memo(a: str, b: str) -> int:
    """Recursive Levenshtein with manual memoization."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    memo: Dict[Tuple[int, int], int] = {}

    def rec(i: int, j: int) -> int:
        if i == 0:
            return j
        if j == 0:
            return i
        key = (i, j)
        if key in memo:
            return memo[key]
        cost = 0 if a[i - 1] == b[j - 1] else 1
        r = min(rec(i - 1, j) + 1, rec(i, j - 1) + 1,
                rec(i - 1, j - 1) + cost)
        memo[key] = r
        return r

    return rec(len(a), len(b))

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert levenshtein_memo("kitten", "sitting") == 3
    assert levenshtein_memo("", "abc") == 3
    assert levenshtein_memo("abc", "abc") == 0
    assert levenshtein_memo("flaw", "lawn") == 2
    try:
        levenshtein_memo("a", 6)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("47-memo OK")


if __name__ == "__main__":
    main()
