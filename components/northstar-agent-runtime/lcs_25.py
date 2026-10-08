"""Word-level LCS (reconstruction)

What this IS: returns one longest common word sequence as a list of tokens.

What this IS NOT:
* the length-only variant -- see lcs_24.
* character reconstruction -- see lcs_03.
"""

from __future__ import annotations

import ast
from typing import List
#: Module version.
LCS_25_VERSION = "lcs-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-25.v1"


def lcs_words(a: str, b: str) -> List[str]:
    # Backtrack a token-level DP table.
    ta, tb = a.split(), b.split()
    m, n = len(ta), len(tb)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if ta[i - 1] == tb[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    i, j, out = m, n, []
    while i > 0 and j > 0:
        if ta[i - 1] == tb[j - 1]:
            out.append(ta[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return list(reversed(out))

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "typing"}
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
    assert lcs_words("the cat sat", "the dog sat") == ["the", "sat"]
    assert lcs_words("a b", "c d") == []
    assert lcs_words("", "x") == []
    assert lcs_words("a b c", "a b c") == ["a", "b", "c"]
    r = lcs_words("a x b y c", "a b c")
    assert r == ["a", "b", "c"]
    assert stdlib_only()
    print("25-ok OK")


if __name__ == "__main__":
    main()
