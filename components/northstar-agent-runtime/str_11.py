"""Longest common subsequence: LCS length + reconstruction.

Classic DP; length in O(min) space, one LCS string via full table backtrack.

What this IS: a real LCS implementation.
What this IS NOT: all LCS enumerations; exponential worst case.
"""

from __future__ import annotations

import ast

#: Module version.
STR_11_VERSION = "str-lcs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-lcs.v1"


class StrError(Exception):
    """Fail-closed."""


def lcs_length(a: str, b: str) -> int:
    """Length of the longest common subsequence."""
    if len(a) < len(b):
        a, b = b, a
    prev = [0] * (len(b) + 1)
    for i in range(1, len(a) + 1):
        cur = [0] * (len(b) + 1)
        for j in range(1, len(b) + 1):
            if a[i - 1] == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev = cur
    return prev[len(b)]


def _is_subseq(sub: str, s: str) -> bool:
    it = iter(s)
    return all(ch in it for ch in sub)


def lcs_string(a: str, b: str) -> str:
    """Return one longest common subsequence."""
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m):
        for j in range(n):
            if a[i] == b[j]:
                dp[i + 1][j + 1] = dp[i][j] + 1
            else:
                dp[i + 1][j + 1] = dp[i + 1][j] if dp[i + 1][j] >= dp[i][j + 1] else dp[i][j + 1]
    i, j = m, n
    out = []
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


def test_lcs_length():
    assert lcs_length("ABCBDAB", "BDCABA") == 4


def test_lcs_string():
    s = lcs_string("ABCBDAB", "BDCABA")
    assert len(s) == 4
    assert _is_subseq(s, "ABCBDAB") and _is_subseq(s, "BDCABA")


def test_lcs_empty():
    assert lcs_length("", "abc") == 0
    assert lcs_string("abc", "") == ""


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
    test_lcs_length()
    test_lcs_string()
    test_lcs_empty()
    assert stdlib_only()
    print("str-11 OK: lcs")


if __name__ == "__main__":
    main()
