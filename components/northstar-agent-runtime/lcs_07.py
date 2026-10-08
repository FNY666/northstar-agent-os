"""Longest palindromic subsequence length

What this IS: LPS length computed as LCS(s, reverse(s)).

What this IS NOT:
* longest palindromic substring -- contiguous is a different problem.
* the palindrome itself -- see lcs_08 for reconstruction.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_07_VERSION = "lcs-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-07.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def lps_length(s: str) -> int:
    # A palindrome reads the same backwards: LPS(s) = LCS(s, reversed(s)).
    return _lcs_len(s, s[::-1])

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
    assert lps_length("bbbab") == 4
    assert lps_length("cbbd") == 2
    assert lps_length("a") == 1
    assert lps_length("") == 0
    assert lps_length("abcba") == 5
    assert stdlib_only()
    print("07-ok OK")


if __name__ == "__main__":
    main()
