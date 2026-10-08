"""Word-level Damerau (token transpositions)

OSA over word tokens: adjacent word swaps cost 1.

What this IS: optimal string alignment on whitespace-separated words.

What this IS NOT:
* character OSA -- ed_21 works per character.
* word Levenshtein -- ed_20 has no transposition.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_49_VERSION = "ed-49.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-49.v1"


def word_damerau(a: str, b: str) -> int:
    """OSA distance over whitespace-separated words."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    A, B = a.split(), b.split()
    m, n = len(A), len(B)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if A[i - 1] == B[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                           dp[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and A[i - 1] == B[j - 2] and A[i - 2] == B[j - 1]:
                dp[i][j] = min(dp[i][j], dp[i - 2][j - 2] + 1)
    return dp[m][n]

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
    assert word_damerau("a b", "b a") == 1
    assert word_damerau("hello world", "hello world") == 0
    assert word_damerau("the cat sat", "the sat cat") == 1
    assert word_damerau("", "a b") == 2
    try:
        word_damerau("a", 9)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("49-word-damerau OK")


if __name__ == "__main__":
    main()
