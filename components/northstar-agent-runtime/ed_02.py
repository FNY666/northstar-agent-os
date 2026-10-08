"""True Damerau-Levenshtein distance

Levenshtein plus adjacent transposition as a single operation.

What this IS: the true Damerau-Levenshtein algorithm (with the alphabet dictionary), not the restricted variant.

What this IS NOT:
* optimal string alignment -- ed_21 covers the restricted variant.
* a similarity score -- this returns an integer distance.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_02_VERSION = "ed-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-02.v1"


def damerau_levenshtein(a: str, b: str) -> int:
    """True Damerau-Levenshtein distance (adjacent transposition = 1)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    d: Dict[str, int] = {}
    m, n = len(a), len(b)
    inf = m + n
    dp = [[0] * (n + 2) for _ in range(m + 2)]
    dp[0][0] = inf
    for i in range(m + 1):
        dp[i + 1][0] = inf
        dp[i + 1][1] = i
    for j in range(n + 1):
        dp[0][j + 1] = inf
        dp[1][j + 1] = j
    for i in range(1, m + 1):
        db = 0
        for j in range(1, n + 1):
            i1 = d.get(b[j - 1], 0)
            j1 = db
            cost = 1
            if a[i - 1] == b[j - 1]:
                cost = 0
                db = j
            dp[i + 1][j + 1] = min(
                dp[i][j] + cost,
                dp[i + 1][j] + 1,
                dp[i][j + 1] + 1,
                dp[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1),
            )
        d[a[i - 1]] = i
    return dp[m + 1][n + 1]

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
    assert damerau_levenshtein("ca", "abc") == 2
    assert damerau_levenshtein("abcd", "acbd") == 1
    assert damerau_levenshtein("", "") == 0
    assert damerau_levenshtein("abc", "abc") == 0
    assert damerau_levenshtein("a", "b") == 1
    try:
        damerau_levenshtein(None, "abc")
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("02-damerau OK")


if __name__ == "__main__":
    main()
