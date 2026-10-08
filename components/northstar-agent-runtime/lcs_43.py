"""LCS index pairs

What this IS: list of (i, j) index pairs witnessing one LCS.

What this IS NOT:
* the subsequence string -- see lcs_03.
* gapped alignment -- see lcs_37.
"""

from __future__ import annotations

import ast
from typing import List, Tuple
#: Module version.
LCS_43_VERSION = "lcs-43.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-43.v1"


def lcs_pairs(a: str, b: str) -> List[Tuple[int, int]]:
    # Backtrack the table, recording coordinates instead of chars.
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
            out.append((i - 1, j - 1))
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
    assert lcs_pairs("abcde", "ace") == [(0, 0), (2, 1), (4, 2)]
    assert lcs_pairs("abc", "def") == []
    assert lcs_pairs("", "a") == []
    pairs = lcs_pairs("AGGTAB", "GXTXAYB")
    assert len(pairs) == 4 and all("AGGTAB"[i] == "GXTXAYB"[j] for i, j in pairs)
    assert lcs_pairs("abc", "abc") == [(0, 0), (1, 1), (2, 2)]
    assert stdlib_only()
    print("43-ok OK")


if __name__ == "__main__":
    main()
