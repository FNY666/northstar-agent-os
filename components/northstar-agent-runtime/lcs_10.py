"""Shortest common supersequence (reconstruction)

What this IS: returns one shortest common supersequence string.

What this IS NOT:
* the length-only variant -- see lcs_09.
* a canonical SCS -- several may exist; one witness is returned.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_10_VERSION = "lcs-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-10.v1"


def _is_subseq(s: str, t: str) -> bool:
    it = iter(t)
    return all(c in it for c in s)


def scs_string(a: str, b: str) -> str:
    # Walk the LCS table, emitting the non-shared chars from both sides.
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
            out.append(a[i - 1])
            i -= 1
        else:
            out.append(b[j - 1])
            j -= 1
    while i > 0:
        out.append(a[i - 1])
        i -= 1
    while j > 0:
        out.append(b[j - 1])
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
    s = scs_string("abac", "cab")
    assert len(s) == 5 and _is_subseq("abac", s) and _is_subseq("cab", s)
    assert scs_string("abc", "abc") == "abc"
    assert scs_string("", "ab") == "ab"
    s = scs_string("ab", "cd")
    assert len(s) == 4 and _is_subseq("ab", s) and _is_subseq("cd", s)
    s = scs_string("abcde", "ace")
    assert len(s) == 5
    assert stdlib_only()
    print("10-ok OK")


if __name__ == "__main__":
    main()
