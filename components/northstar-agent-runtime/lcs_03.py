"""LCS reconstruction (one subsequence)

What this IS: returns one longest common subsequence string via DP table backtracking.

What this IS NOT:
* all LCS strings -- only one witness is returned.
* just the length -- see lcs_01 for the cheaper length-only DP.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_03_VERSION = "lcs-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-03.v1"


def _is_subseq(s: str, t: str) -> bool:
    it = iter(t)
    return all(c in it for c in s)


def lcs_string(a: str, b: str) -> str:
    # Full DP table, then backtrack to recover one LCS.
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    i, j, out = m, n, []
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            out.append(a[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return "".join(reversed(out))

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
    assert lcs_string("abcde", "ace") == "ace"
    assert lcs_string("abc", "def") == ""
    s = lcs_string("AGGTAB", "GXTXAYB")
    assert len(s) == 4 and _is_subseq(s, "AGGTAB") and _is_subseq(s, "GXTXAYB")
    assert lcs_string("", "abc") == ""
    assert lcs_string("abc", "abc") == "abc"
    assert stdlib_only()
    print("03-ok OK")


if __name__ == "__main__":
    main()
