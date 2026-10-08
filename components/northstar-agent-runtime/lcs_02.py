"""LCS length (one-row DP)

What this IS: LCS length in O(m*n) time and O(min(m,n)) space using a single rolling row.

What this IS NOT:
* the full-table variant -- see lcs_01 when the table itself is needed.
* a subsequence reconstruction -- one row cannot backtrack; see lcs_03.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_02_VERSION = "lcs-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-02.v1"


def lcs_length_1row(a: str, b: str) -> int:
    # O(m*n) time, O(min(m,n)) space single-row DP with diagonal carry.
    if len(a) < len(b):
        a, b = b, a
    prev = [0] * (len(b) + 1)
    for ca in a:
        diag = 0
        for j in range(1, len(b) + 1):
            tmp = prev[j]
            if ca == b[j - 1]:
                prev[j] = diag + 1
            elif tmp < prev[j - 1]:
                prev[j] = prev[j - 1]
            diag = tmp
    return prev[len(b)]

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
    assert lcs_length_1row("abcde", "ace") == 3
    assert lcs_length_1row("", "abc") == 0
    assert lcs_length_1row("abc", "abc") == 3
    assert lcs_length_1row("abc", "def") == 0
    assert lcs_length_1row("AGGTAB", "GXTXAYB") == 4
    assert stdlib_only()
    print("02-ok OK")


if __name__ == "__main__":
    main()
