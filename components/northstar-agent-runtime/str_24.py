"""Shortest common supersequence: DP merge of two strings.

DP on edit-style table, backtrack preferring the shorter path; result contains both inputs as subsequences.

What this IS: a real SCS implementation.
What this IS NOT: k-string SCS (NP-hard).
"""

from __future__ import annotations

import ast

#: Module version.
STR_24_VERSION = "str-scs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-shortest-common-supersequence.v1"


class StrError(Exception):
    """Fail-closed."""


def _is_subseq(sub: str, s: str) -> bool:
    it = iter(s)
    return all(ch in it for ch in sub)


def shortest_common_supersequence(a: str, b: str) -> str:
    """Return one shortest string containing a and b as subsequences."""
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1])
    i, j = m, n
    out = []
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            out.append(a[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] < dp[i][j - 1]:
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


def test_scs_length():
    assert len(shortest_common_supersequence("abac", "cab")) == 5


def test_scs_contains():
    s = shortest_common_supersequence("abac", "cab")
    assert _is_subseq("abac", s) and _is_subseq("cab", s)


def test_scs_identical():
    assert shortest_common_supersequence("abc", "abc") == "abc"


def test_scs_empty():
    assert shortest_common_supersequence("", "abc") == "abc"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_scs_length()
    test_scs_contains()
    test_scs_identical()
    test_scs_empty()
    assert stdlib_only()
    print("str-24 OK: scs")


if __name__ == "__main__":
    main()
