"""LCS length (top-down memoization)

What this IS: LCS length via recursion with explicit memo dict (top-down DP).

What this IS NOT:
* an lru_cache variant -- see lcs_31 for the functools version.
* a tail-call-safe variant -- deep inputs can hit recursion limits; see lcs_49.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_04_VERSION = "lcs-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-04.v1"


def lcs_memo(a: str, b: str) -> int:
    # Top-down DP with an explicit memo dictionary.
    memo = {}

    def rec(i: int, j: int) -> int:
        if i == 0 or j == 0:
            return 0
        key = (i, j)
        if key not in memo:
            if a[i - 1] == b[j - 1]:
                memo[key] = rec(i - 1, j - 1) + 1
            else:
                x, y = rec(i - 1, j), rec(i, j - 1)
                memo[key] = x if x >= y else y
        return memo[key]

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
    assert lcs_memo("abcde", "ace") == 3
    assert lcs_memo("", "abc") == 0
    assert lcs_memo("abc", "abc") == 3
    assert lcs_memo("abc", "def") == 0
    assert lcs_memo("AGGTAB", "GXTXAYB") == 4
    assert stdlib_only()
    print("04-ok OK")


if __name__ == "__main__":
    main()
