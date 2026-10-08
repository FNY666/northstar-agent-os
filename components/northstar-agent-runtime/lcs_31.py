"""LCS length (functools.lru_cache)

What this IS: top-down LCS using functools.lru_cache instead of a hand-rolled memo dict.

What this IS NOT:
* the manual-memo variant -- see lcs_04.
* deep inputs -- recursion limits still apply; see lcs_49.
"""

from __future__ import annotations

import ast
import functools
#: Module version.
LCS_31_VERSION = "lcs-31.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-31.v1"


def lcs_lru(a: str, b: str) -> int:
    # lru_cache gives us memoization for free on the (i, j) state.
    @functools.lru_cache(maxsize=None)
    def rec(i: int, j: int) -> int:
        if i == 0 or j == 0:
            return 0
        if a[i - 1] == b[j - 1]:
            return rec(i - 1, j - 1) + 1
        x, y = rec(i - 1, j), rec(i, j - 1)
        return x if x >= y else y

    return rec(len(a), len(b))

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "functools"}
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
    assert lcs_lru("abcde", "ace") == 3
    assert lcs_lru("", "abc") == 0
    assert lcs_lru("abc", "abc") == 3
    assert lcs_lru("abc", "def") == 0
    assert lcs_lru("AGGTAB", "GXTXAYB") == 4
    assert stdlib_only()
    print("31-ok OK")


if __name__ == "__main__":
    main()
