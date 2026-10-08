"""Longest palindromic subsequence (reconstruction)

What this IS: returns one longest palindromic subsequence string.

What this IS NOT:
* the length-only variant -- see lcs_07.
* palindromic substrings -- contiguity is not required here.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_08_VERSION = "lcs-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-08.v1"


def _is_subseq(s: str, t: str) -> bool:
    it = iter(t)
    return all(c in it for c in s)


def lps_string(s: str) -> str:
    # Backtrack LCS(s, reversed(s)); the witness is a palindrome.
    t = s[::-1]
    m, n = len(s), len(t)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s[i - 1] == t[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    i, j, out = m, n, []
    while i > 0 and j > 0:
        if s[i - 1] == t[j - 1]:
            out.append(s[i - 1])
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
    r = lps_string("bbbab")
    assert len(r) == 4 and r == r[::-1] and _is_subseq(r, "bbbab")
    r = lps_string("cbbd")
    assert len(r) == 2 and r == r[::-1]
    assert lps_string("a") == "a"
    assert lps_string("") == ""
    assert lps_string("abcba") == "abcba"
    assert stdlib_only()
    print("08-ok OK")


if __name__ == "__main__":
    main()
